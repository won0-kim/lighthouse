import os
import struct
import logging
import tempfile
import threading
from collections import defaultdict

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("Lighthouse.MCP")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

#------------------------------------------------------------------------------
# Module-level State
#------------------------------------------------------------------------------

_server_thread = None
_server_loop = None
_get_context = None

mcp = FastMCP("lighthouse")

#------------------------------------------------------------------------------
# Helpers
#------------------------------------------------------------------------------

def _resolve_context():
    """
    Return the existing Lighthouse context, if one has already been created.
    Does NOT create a new context (which would deadlock from a background thread).
    """
    if _get_context is None:
        return None
    # access the core's lighthouse_contexts dict directly
    # to avoid triggering context creation from a background thread
    core = getattr(_get_context, '__self__', None)
    if core is None:
        return None
    contexts = getattr(core, 'lighthouse_contexts', {})
    if not contexts:
        return None
    # return the first (and usually only) context
    return next(iter(contexts.values()), None)


def _is_tinyinst(filepath):
    """
    Check if a file looks like TinyInst coverage format (module+offset per line).
    """
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if "+" in line:
                    return True
                return False
    except Exception:
        return False


def _is_address_trace(filepath):
    """
    Check if a file looks like an address trace (one hex address per line).
    """
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if "+" in line:
                    return False
                int(line, 16)
                return True
    except Exception:
        return False


def _tinyinst_to_addresses(filepath):
    """
    Parse a TinyInst coverage file (module+offset per line).
    Returns dict of {module_name: set of offsets}.
    """
    modules = defaultdict(set)
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "+" not in line:
                continue
            mod, off_str = line.split("+", 1)
            off_str = off_str.split()[0]  # strip annotations like "(FUNC_NAME)"
            try:
                offset = int(off_str, 16)
                modules[mod].add(offset)
            except ValueError:
                continue
    return dict(modules)


def _trace_to_addresses(filepath, metadata):
    """
    Parse an address trace file (one hex VA per line).
    Converts absolute VAs to imagebase-relative offsets.
    Returns dict of {module_name: set of offsets}.
    """
    imagebase = metadata.imagebase if metadata and metadata.cached else 0
    module_name = metadata.filename if metadata else "unknown"
    offsets = set()
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                addr = int(line, 16)
                offsets.add(addr - imagebase)
            except ValueError:
                continue
    if not offsets:
        return {}
    return {module_name: offsets}


def _get_call_boundaries(node_ranges):
    """
    Query IDA for call instruction locations within the given nodes.
    node_ranges: list of (node_va, node_size)
    Returns {node_va: sorted list of (call_va, call_end_va)}
    """
    import idaapi
    result = [None]

    def _do():
        import idc
        call_map = {}
        for node_va, node_size in node_ranges:
            calls = []
            cur = node_va
            end = node_va + node_size
            while cur < end and cur != idc.BADADDR:
                mnem = idc.print_insn_mnem(cur)
                nxt = idc.next_head(cur, end)
                if nxt == idc.BADADDR:
                    nxt = end
                if mnem in ('BL', 'BLX', 'CALL'):
                    calls.append((cur, nxt))
                cur = nxt
            if calls:
                call_map[node_va] = calls
        result[0] = call_map

    idaapi.execute_sync(_do, idaapi.MFF_READ)
    return result[0]


def _addresses_to_drcov(module_offsets, metadata=None):
    """
    Convert coverage offsets to a temporary drcov v2 file with
    call-boundary-aware BB expansion.

    For each hit, coverage extends from the hit address to the next call
    instruction (inclusive) or node end. If execution returns from a call,
    TinyInst logs the return address as a new hit, so coverage resumes there.

    module_offsets: dict of {module_name: set of offsets relative to imagebase}
    metadata: Lighthouse metadata for node/call info.
    Returns path to temp drcov file, or None.
    """
    if not module_offsets:
        return None

    import bisect

    node_offsets = []     # sorted list of (rel_offset, size, node_va)
    node_offset_keys = [] # just rel_offsets for bisect
    imagebase = 0
    call_map = {}

    if metadata and metadata.cached:
        imagebase = metadata.imagebase

        for node_addr, node_meta in metadata.nodes.items():
            rel = node_addr - imagebase
            node_offsets.append((rel, node_meta.size, node_addr))
        node_offsets.sort()
        node_offset_keys = [n[0] for n in node_offsets]

        # collect only nodes that contain hits, then batch query calls
        hit_nodes = set()
        for offsets in module_offsets.values():
            for offset in offsets:
                idx = bisect.bisect_right(node_offset_keys, offset) - 1
                if idx >= 0:
                    node_off, node_sz, node_va = node_offsets[idx]
                    if node_off <= offset < node_off + node_sz:
                        hit_nodes.add((node_va, node_sz))

        if hit_nodes:
            call_map = _get_call_boundaries(list(hit_nodes))

    mod_list = sorted(module_offsets.keys())
    mod_index = {name: i for i, name in enumerate(mod_list)}

    bb_entries = []
    seen_ranges = set()

    for mod_name in mod_list:
        mid = mod_index[mod_name]
        for offset in sorted(module_offsets[mod_name]):
            if node_offset_keys:
                idx = bisect.bisect_right(node_offset_keys, offset) - 1
                if idx >= 0:
                    node_off, node_sz, node_va = node_offsets[idx]
                    if node_off <= offset < node_off + node_sz:
                        hit_va = offset + imagebase
                        node_end_va = node_va + node_sz

                        # default: extend to node end
                        range_end_va = node_end_va

                        # stop at the first call at or after the hit
                        if node_va in call_map:
                            for call_va, call_end_va in call_map[node_va]:
                                if call_va >= hit_va:
                                    range_end_va = call_end_va
                                    break

                        range_start = offset
                        range_size = range_end_va - hit_va
                        key = (range_start, range_size)
                        if key not in seen_ranges:
                            seen_ranges.add(key)
                            bb_entries.append((range_start, range_size, mid))
                        continue

            # fallback: no metadata or offset not in any node
            bb_entries.append((offset, 1, mid))

    fd, tmp_path = tempfile.mkstemp(suffix=".drcov")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b"DRCOV VERSION: 2\n")
            f.write(b"DRCOV FLAVOR: drcov\n")
            f.write(("Module Table: version 2, count %d\n" % len(mod_list)).encode())
            f.write(b"Columns: id, base, end, entry, checksum, timestamp, path\n")
            for i, name in enumerate(mod_list):
                f.write((" %d, 0x0000000000000000, 0x0000000100000000, 0x0000000000000000, 0x00000000, 0x00000000, %s\n" % (i, name)).encode())
            f.write(("BB Table: %d bbs\n" % len(bb_entries)).encode())
            for offset, size, mod_id in bb_entries:
                f.write(struct.pack("<IHH", offset, size, mod_id))
    except Exception:
        os.unlink(tmp_path)
        raise

    return tmp_path

#------------------------------------------------------------------------------
# MCP Tools
#------------------------------------------------------------------------------

@mcp.tool()
def load_coverage(filepaths: list[str]) -> dict:
    """
    Load one or more coverage files into the current IDA database.

    Each filepath should point to a valid coverage file on disk.
    Supported formats: drcov (drcov.log), TinyInst (coverage.txt, module+offset per line), mod+off, tenet, address trace.
    TinyInst coverage.txt files are automatically converted to drcov format before loading.
    Returns a summary of successfully loaded coverages and any errors encountered.
    """
    logger.info("load_coverage called: filepaths=%s", filepaths)
    lctx = _resolve_context()
    if lctx is None:
        return {"error": "Lighthouse context not available. Please open the Coverage Overview in IDA first (View -> Open subviews -> Coverage Overview), then retry."}

    if not lctx.metadata.cached:
        return {"error": "Database metadata not yet cached. Please open the Coverage Overview in IDA first, then retry."}

    # validate file existence and convert custom formats to drcov
    errors = []
    valid_paths = []
    tmp_files = []
    for fp in filepaths:
        if not os.path.isfile(fp):
            errors.append("File not found: %s" % fp)
            continue

        # detect format and convert to drcov with call-aware BB expansion
        module_offsets = None
        if _is_tinyinst(fp):
            module_offsets = _tinyinst_to_addresses(fp)
        elif _is_address_trace(fp):
            module_offsets = _trace_to_addresses(fp, lctx.metadata)

        if module_offsets is not None:
            try:
                tmp_path = _addresses_to_drcov(module_offsets, metadata=lctx.metadata)
                if tmp_path:
                    valid_paths.append(tmp_path)
                    tmp_files.append(tmp_path)
                else:
                    errors.append("No coverage data in file: %s" % fp)
            except Exception as e:
                errors.append("Failed to convert coverage file %s: %s" % (fp, e))
        else:
            valid_paths.append(fp)

    if not valid_paths:
        return {"loaded": [], "errors": errors}

    try:
        # load coverage files in headless mode (no UI dialogs)
        created_coverage, load_errors = lctx.director.load_coverage_files(
            valid_paths, headless=True
        )

        loaded_names = [cov.name for cov in created_coverage] if created_coverage else []

        # collect error messages from the load process
        for error_type, error_list in load_errors.items():
            for e in error_list:
                errors.append(str(e))
    finally:
        # clean up temp drcov files
        for tmp in tmp_files:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    return {"loaded": loaded_names, "errors": errors}


@mcp.tool()
def find_coverage_by_function(function_name: str, coverage_name: str = "") -> dict:
    """
    Search for functions matching a name pattern and return their coverage data.

    Performs a case-insensitive substring match against all function names in the database.
    Optionally filter to a specific coverage set by name. Results are sorted by
    instruction coverage percentage (descending). Maximum 100 results returned.
    """
    logger.info("find_coverage_by_function called: function_name=%r, coverage_name=%r", function_name, coverage_name)
    lctx = _resolve_context()
    if lctx is None:
        return {"error": "Lighthouse context not available. Please open the Coverage Overview in IDA first (View -> Open subviews -> Coverage Overview), then retry."}

    director = lctx.director
    metadata = lctx.metadata
    search_lower = function_name.lower()

    # find matching functions in metadata
    matching_functions = []
    for func_addr, func_meta in metadata.functions.items():
        if search_lower in func_meta.name.lower():
            matching_functions.append((func_addr, func_meta))

    if not matching_functions:
        return {"matches": [], "total_matches": 0}

    # determine which coverage sets to search
    if coverage_name:
        cov = director.get_coverage(coverage_name)
        if cov is None:
            return {"error": "Coverage '%s' not found" % coverage_name}
        coverage_sets = [(coverage_name, cov)]
    else:
        coverage_sets = []
        for name in director.coverage_names:
            coverage_sets.append((name, director.get_coverage(name)))

    # collect results
    results = []
    for func_addr, func_meta in matching_functions:
        for cov_name, cov in coverage_sets:
            func_cov = cov.functions.get(func_addr)
            instruction_percent = func_cov.instruction_percent if func_cov else 0.0
            node_percent = func_cov.node_percent if func_cov else 0.0
            instructions_executed = func_cov.instructions_executed if func_cov else 0

            results.append({
                "name": func_meta.name,
                "address": "0x%X" % func_addr,
                "coverage_name": cov_name,
                "instruction_percent": round(instruction_percent * 100, 2),
                "node_percent": round(node_percent * 100, 2),
                "instructions_executed": instructions_executed,
                "instruction_count": func_meta.instruction_count,
            })

    # sort by instruction_percent descending
    results.sort(key=lambda x: x["instruction_percent"], reverse=True)

    total_matches = len(results)
    results = results[:100]

    return {"matches": results, "total_matches": total_matches}


@mcp.tool()
def rank_functions(limit: int = 10, sort: str = "desc", min_percent: float = -1, max_percent: float = -1, min_instructions: int = 0) -> dict:
    """
    Rank functions by instruction coverage percentage.

    Returns the top or bottom N functions sorted by coverage.
    Use sort="desc" for highest coverage first, sort="asc" for lowest first.
    Optionally filter by min_percent and/or max_percent (0-100 scale).
    Use min_instructions to exclude small stub functions (e.g. min_instructions=10).
    Set min_percent=0.01 with sort="asc" to skip completely uncovered functions.
    Set max_percent=0 to find only uncovered functions.
    """
    logger.info("rank_functions called: limit=%d, sort=%r, min_percent=%s, max_percent=%s, min_instructions=%d", limit, sort, min_percent, max_percent, min_instructions)
    lctx = _resolve_context()
    if lctx is None:
        return {"error": "Lighthouse context not available. Please open the Coverage Overview in IDA first (View -> Open subviews -> Coverage Overview), then retry."}

    director = lctx.director
    metadata = lctx.metadata
    cov = director.aggregate

    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100

    results = []
    for func_addr, func_meta in metadata.functions.items():
        if func_meta.instruction_count < min_instructions:
            continue

        func_cov = cov.functions.get(func_addr)
        pct = round((func_cov.instruction_percent * 100) if func_cov else 0.0, 2)

        if min_percent >= 0 and pct < min_percent:
            continue
        if max_percent >= 0 and pct > max_percent:
            continue

        results.append({
            "name": func_meta.name,
            "address": "0x%X" % func_addr,
            "instruction_percent": pct,
            "instruction_count": func_meta.instruction_count,
        })

    reverse = sort.lower() != "asc"
    results.sort(key=lambda x: x["instruction_percent"], reverse=reverse)

    total = len(results)
    results = results[:limit]

    return {"functions": results, "total": total, "limit": limit, "sort": sort}


def _decompile_with_coverage(func_addr, covered_addrs):
    """
    Decompile a function on the main thread and annotate each pseudocode line
    with coverage status. Returns a list of {line, text, covered} dicts, or None.
    """
    import idaapi

    result = [None]

    def _do():
        try:
            import ida_hexrays
            import ida_lines
        except ImportError:
            return

        cfunc = ida_hexrays.decompile(func_addr)
        if cfunc is None:
            return

        # get pseudocode text
        sv = cfunc.get_pseudocode()
        lines = []
        for i in range(sv.size()):
            lines.append({
                "line": i + 1,
                "text": ida_lines.tag_remove(sv[i].line),
                "covered": None,
            })

        # try to build EA -> line mapping via ctree visitor
        try:
            ea_to_line = {}

            class Visitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

                def _map(self, item):
                    ea = item.ea
                    if ea != idaapi.BADADDR and ea not in ea_to_line:
                        coords = cfunc.find_item_coords(item)
                        if coords is not None:
                            # coords is (y, x) tuple
                            y = coords[0] if hasattr(coords, '__getitem__') else coords
                            ea_to_line[ea] = y
                    return 0

                def visit_insn(self, i):
                    return self._map(i)

                def visit_expr(self, e):
                    return self._map(e)

            Visitor().apply_to(cfunc.body, None)

            # annotate lines
            for ea, ln in ea_to_line.items():
                if isinstance(ln, int) and 0 <= ln < len(lines):
                    if ea in covered_addrs:
                        lines[ln]["covered"] = True
                    elif lines[ln]["covered"] is None:
                        lines[ln]["covered"] = False

            # mark remaining code lines as False
            for lr in lines:
                if lr["covered"] is None:
                    text = lr["text"].strip()
                    if text and text not in ("{", "}", ""):
                        lr["covered"] = False

        except Exception:
            logger.exception("line-level coverage mapping failed")

        result[0] = lines

    idaapi.execute_sync(_do, idaapi.MFF_READ)
    return result[0]


@mcp.tool()
def get_function_coverage(function_name: str, coverage_name: str = "", offset: int = 0, limit: int = 0, filter: str = "", compact: bool = True) -> dict:
    """
    Get decompiled pseudocode of a function with per-line coverage annotation.

    Returns decompiled pseudocode where each line is marked as covered (true),
    not covered (false), or unknown (null). Useful for identifying exactly
    which code paths are missed. If coverage_name is omitted, uses the aggregate.

    Args:
        offset: Skip the first N pseudocode lines (0-based). Default 0.
        limit:  Return at most N pseudocode lines. 0 means all. Default 0.
        filter: Filter lines by coverage status: "uncovered", "covered", or "" (all). Default "".
        compact: If true, return pseudocode as a compact text string instead of JSON array.
                 Format: "[+] covered_line" / "[-] uncovered_line" / "[ ] unknown_line".
                 This dramatically reduces output size. Default true.
    """
    logger.info("get_function_coverage called: function_name=%r, coverage_name=%r", function_name, coverage_name)
    lctx = _resolve_context()
    if lctx is None:
        return {"error": "Lighthouse context not available. Please open the Coverage Overview in IDA first (View -> Open subviews -> Coverage Overview), then retry."}

    director = lctx.director
    metadata = lctx.metadata

    # find the function by exact or substring match
    target_func = None
    search_lower = function_name.lower()

    # try exact match first
    for func_addr, func_meta in metadata.functions.items():
        if func_meta.name.lower() == search_lower:
            target_func = (func_addr, func_meta)
            break

    # fallback to substring match (pick first)
    if target_func is None:
        for func_addr, func_meta in metadata.functions.items():
            if search_lower in func_meta.name.lower():
                target_func = (func_addr, func_meta)
                break

    if target_func is None:
        return {"error": "Function '%s' not found" % function_name}

    func_addr, func_meta = target_func

    # get coverage object
    if coverage_name:
        cov = director.get_coverage(coverage_name)
        if cov is None:
            return {"error": "Coverage '%s' not found" % coverage_name}
    else:
        cov = director.aggregate

    func_cov = cov.functions.get(func_addr)

    # collect all covered addresses in this function
    covered_addrs = set()
    if func_cov:
        for node_cov in func_cov.nodes.values():
            covered_addrs.update(node_cov.executed_instructions.keys())

    # decompile and annotate pseudocode lines with coverage
    decompiled_lines = _decompile_with_coverage(func_addr, covered_addrs)

    result = {
        "function": func_meta.name,
        "address": "0x%X" % func_addr,
        "coverage_name": coverage_name or "(aggregate)",
        "instruction_percent": round((func_cov.instruction_percent * 100) if func_cov else 0.0, 2),
    }

    if decompiled_lines is not None:
        total_lines = len(decompiled_lines)

        # apply filter
        filter_lower = filter.lower()
        if filter_lower == "uncovered":
            decompiled_lines = [l for l in decompiled_lines if l["covered"] is False]
        elif filter_lower == "covered":
            decompiled_lines = [l for l in decompiled_lines if l["covered"] is True]

        filtered_count = len(decompiled_lines)

        # apply pagination
        if offset > 0:
            decompiled_lines = decompiled_lines[offset:]
        if limit > 0:
            decompiled_lines = decompiled_lines[:limit]

        if compact:
            # compact text format: much smaller than JSON array
            markers = {True: "[+]", False: "[-]", None: "[ ]"}
            lines_text = []
            for l in decompiled_lines:
                marker = markers.get(l["covered"], "[ ]")
                lines_text.append("%s %4d: %s" % (marker, l["line"], l["text"]))
            result["pseudocode"] = "\n".join(lines_text)
        else:
            result["pseudocode"] = decompiled_lines

        result["total_lines"] = total_lines
        result["filtered_lines"] = filtered_count
        result["returned_lines"] = len(decompiled_lines) if not compact else len(lines_text)
        if filter_lower:
            result["filter"] = filter_lower
        if offset > 0:
            result["offset"] = offset

    return result


@mcp.tool()
def list_coverages(offset: int = 0, limit: int = 20) -> dict:
    """
    List all loaded coverage sets with summary statistics.

    Returns paginated results of loaded coverages including name, shorthand alias,
    filepath, instruction coverage percentage, and function coverage count.
    Also includes aggregate coverage information.
    """
    logger.info("list_coverages called: offset=%d, limit=%d", offset, limit)
    lctx = _resolve_context()
    if lctx is None:
        return {"error": "Lighthouse context not available. Please open the Coverage Overview in IDA first (View -> Open subviews -> Coverage Overview), then retry."}

    director = lctx.director

    # clamp limit
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100

    all_names = director.coverage_names
    total = len(all_names)

    # paginate
    page_names = all_names[offset:offset + limit]

    coverages = []
    for name in page_names:
        cov = director.get_coverage(name)
        if cov is None:
            continue

        shorthand = director.get_shorthand(name)
        functions_with_coverage = len(cov.functions) if cov.functions else 0

        coverages.append({
            "name": name,
            "shorthand": shorthand or "",
            "filepath": cov.filepath or "",
            "instruction_percent": round(cov.instruction_percent * 100, 2),
            "functions_with_coverage": functions_with_coverage,
        })

    # aggregate info
    agg = director.aggregate
    aggregate_info = {
        "instruction_percent": round(agg.instruction_percent * 100, 2),
        "functions_with_coverage": len(agg.functions) if agg.functions else 0,
    }

    return {
        "coverages": coverages,
        "aggregate": aggregate_info,
        "total": total,
        "offset": offset,
        "limit": limit,
    }

#------------------------------------------------------------------------------
# Server Lifecycle
#------------------------------------------------------------------------------

def start_mcp_server(get_context, host="127.0.0.1", port=None):
    """
    Start the MCP SSE server in a background daemon thread.
    Port can be set via LIGHTHOUSE_PORT environment variable (default: 1337).
    """
    import asyncio
    import uvicorn

    if port is None:
        port = int(os.environ.get("LIGHTHOUSE_PORT", "1337"))

    global _server_thread, _server_loop, _get_context
    _get_context = get_context

    starlette_app = mcp.streamable_http_app()

    def _run_server():
        global _server_loop
        _server_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_server_loop)

        config = uvicorn.Config(
            app=starlette_app,
            host=host,
            port=port,
            log_level="warning",
            loop="asyncio",
        )
        server = uvicorn.Server(config)

        _server_loop.run_until_complete(server.serve())

    _server_thread = threading.Thread(target=_run_server, name="LighthouseMCP", daemon=True)
    _server_thread.start()

    logger.info("MCP server started on %s:%d" % (host, port))


def stop_mcp_server():
    """
    Stop the MCP SSE server and clean up resources.
    """
    global _server_thread, _server_loop, _get_context

    if _server_loop is not None:
        _server_loop.call_soon_threadsafe(_server_loop.stop)

    if _server_thread is not None:
        _server_thread.join(timeout=5)

    _server_thread = None
    _server_loop = None
    _get_context = None

    logger.info("MCP server stopped")
