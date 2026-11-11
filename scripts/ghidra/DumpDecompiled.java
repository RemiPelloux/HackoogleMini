// Ghidra headless script: decompile every function and print C to stdout.
//
// Used by scripts/ghidra-headless.sh via -postScript DumpDecompiled.java.
// The texual output goes into the headless log, which we tee into evidence/.
//
// @category REA

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpDecompiled extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) {
            println("// decompiler failed to open program");
            return;
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        int ok = 0, fail = 0;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                println("/* ==== " + f.getEntryPoint() + "  " + f.getName() + " ==== */");
                println(res.getDecompiledFunction().getC());
                ok++;
            } else {
                fail++;
            }
        }
        println("// decompiled: " + ok + "  failed: " + fail);
        ifc.dispose();
    }
}
