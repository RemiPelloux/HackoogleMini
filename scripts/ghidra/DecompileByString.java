// Ghidra headless script: decompile only the functions that reference strings matching a
// regex, plus their direct callees (depth 1). Keeps output small for stripped binaries
// where log/assert strings are the only anchors.
//
//   analyzeHeadless ... -postScript DecompileByString.java "<java-regex>" [callee-depth]
//   analyzeHeadless ... -postScript DecompileByString.java "@1fb42c,1fb1d8" [callee-depth]
//   analyzeHeadless ... -postScript DecompileByString.java "=SymbolName" [callee-depth]   (callers)
//
// Re-run on an existing project without re-analysis:
//   analyzeHeadless work/ghidra <proj> -process -noanalysis -readOnly -scriptPath scripts/ghidra \
//       -postScript DecompileByString.java "@<hex>,<hex>" 1
//
// @category REA

import java.util.*;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class DecompileByString extends GhidraScript {
    // Walk back (max 4 KB) to a Thumb "push {..., lr}" (0xb5xx) or "push.w {..., lr}"
    // (0xe92d 0x4xxx) and create a function there.
    private Function createAtPrologue(Address at) throws Exception {
        Address a = at.getNewAddress(at.getOffset() & ~1L);
        for (int i = 0; i < 2048; i++, a = a.subtract(2)) {
            int h = getShort(a) & 0xffff;
            boolean push16 = (h & 0xff00) == 0xb500;
            boolean push32 = h == 0xe92d && (getShort(a.add(2)) & 0x4000) != 0;
            if (!push16 && !push32) continue;
            Function f = getFunctionAt(a);
            if (f == null) {
                // Analysis often left these as ARM-mode garbage: clear, force Thumb, redo.
                Address end = a.add(0x1000);
                clearListing(a, end);
                ghidra.program.model.lang.Register tm = currentProgram.getRegister("TMode");
                currentProgram.getProgramContext().setValue(tm, a, end, java.math.BigInteger.ONE);
                disassemble(a);
                f = getFunctionAt(a);
            }
            if (f == null) f = createFunction(a, null);
            if (f != null) return f;   // body may not reach `at` if flow analysis stops early
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("usage: DecompileByString.java <regex> [depth]"); return; }
        Pattern p = Pattern.compile(a[0]);
        int depth = a.length > 1 ? Integer.parseInt(a[1]) : 1;

        Listing listing = currentProgram.getListing();
        Map<Function, Set<String>> anchors = new LinkedHashMap<>();
        if (a[0].startsWith("@")) {            // "@1fb42c,1fb1d8": explicit function addresses
            boolean force = a[0].startsWith("@!"); // "@!addr": addr is a Thumb function start; rebuild it
            for (String h : a[0].substring(force ? 2 : 1).split(",")) {
                Address at = toAddr(Long.parseLong(h, 16));
                if (force) {
                    Function old = getFunctionContaining(at);
                    if (old != null) removeFunction(old);
                    Function g = getFunctionAt(at);
                    if (g != null) removeFunction(g);
                }
                Function f = force ? null : getFunctionContaining(at);
                if (f == null) f = createAtPrologue(at);   // analysis missed it; -readOnly keeps DB clean
                if (f != null) anchors.put(f, new TreeSet<>(List.of("@" + h)));
                else println("// no function for @" + h);
            }
        }
        else if (a[0].startsWith("=")) {       // "=NewLibassistantEntrypoint": callers of a symbol
            List<Address> targets = new ArrayList<>();
            for (ghidra.program.model.symbol.Symbol s : currentProgram.getSymbolTable().getSymbols(a[0].substring(1))) {
                targets.add(s.getAddress());
                // imports: calls go to the PLT thunks, which getSymbols() does not return
                if (s.getObject() instanceof Function fn && fn.getFunctionThunkAddresses(true) != null)
                    targets.addAll(Arrays.asList(fn.getFunctionThunkAddresses(true)));
            }
            for (Address t : targets)
                for (Reference r : getReferencesTo(t)) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f != null && !f.isThunk()) anchors.computeIfAbsent(f, k -> new TreeSet<>()).add(a[0]);
                    else if (f != null)            // PLT thunk: take the thunk's callers
                        for (Reference r2 : getReferencesTo(f.getEntryPoint())) {
                            Function g = getFunctionContaining(r2.getFromAddress());
                            if (g != null) anchors.computeIfAbsent(g, k -> new TreeSet<>()).add(a[0] + " via thunk");
                        }
                }
        }
        else for (Data d : listing.getDefinedData(true)) {
            if (monitor.isCancelled()) break;
            if (!d.hasStringValue()) continue;
            String s = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (s == null || !p.matcher(s).find()) continue;
            for (Reference r : getReferencesTo(d.getAddress())) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) anchors.computeIfAbsent(f, k -> new TreeSet<>()).add(s);
            }
        }

        Set<Function> todo = new LinkedHashSet<>(anchors.keySet());
        Set<Function> frontier = new LinkedHashSet<>(todo);
        for (int i = 0; i < depth; i++) {
            Set<Function> next = new LinkedHashSet<>();
            for (Function f : frontier)
                for (Function c : f.getCalledFunctions(monitor))
                    if (!c.isThunk() && !c.isExternal() && todo.add(c)) next.add(c);
            frontier = next;
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        println("// anchors: " + anchors.size() + "  total functions: " + todo.size());
        for (Function f : todo) {
            DecompileResults res = ifc.decompileFunction(f, 120, monitor);
            println("/* ==== " + f.getEntryPoint() + "  " + f.getName()
                    + (anchors.containsKey(f) ? "  ANCHOR " + anchors.get(f) : "  (callee)") + " ==== */");
            println(res != null && res.decompileCompleted()
                    ? res.getDecompiledFunction().getC() : "// decompile failed");
        }
        ifc.dispose();
    }
}
