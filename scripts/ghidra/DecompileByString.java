// Ghidra headless script: decompile only the functions that reference strings matching a
// regex, plus their direct callees (depth 1). Keeps output small for stripped binaries
// where log/assert strings are the only anchors.
//
//   analyzeHeadless ... -postScript DecompileByString.java "<java-regex>" [callee-depth]
//   analyzeHeadless ... -postScript DecompileByString.java "@1fb42c,1fb1d8" [callee-depth]
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
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("usage: DecompileByString.java <regex> [depth]"); return; }
        Pattern p = Pattern.compile(a[0]);
        int depth = a.length > 1 ? Integer.parseInt(a[1]) : 1;

        Listing listing = currentProgram.getListing();
        Map<Function, Set<String>> anchors = new LinkedHashMap<>();
        if (a[0].startsWith("@")) {            // "@1fb42c,1fb1d8": explicit function addresses
            for (String h : a[0].substring(1).split(",")) {
                Function f = getFunctionContaining(toAddr(Long.parseLong(h, 16)));
                if (f != null) anchors.put(f, new TreeSet<>(List.of("@" + h)));
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
