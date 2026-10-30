package com.acas.util;

import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.SwingUtilities;

/** Bounded local diagnostics; no request, response or credential data is read. */
public final class UiFreezeDiagnostics implements AutoCloseable {
    private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"ACAS-UI-watchdog");t.setDaemon(true);return t;});
    private final AtomicLong pending=new AtomicLong();
    private final java.util.function.Consumer<String> report;
    private int reports;
    private boolean reported;
    public UiFreezeDiagnostics(java.util.function.Consumer<String> report){this.report=report;}
    public void start(){worker.scheduleWithFixedDelay(this::tick,1,1,TimeUnit.SECONDS);}
    private void tick(){
        try {
            long now=System.nanoTime(),sent=pending.get();
            if(sent==0){
                reported=false;pending.set(now);
                SwingUtilities.invokeLater(()->pending.set(0));
            } else if(!reported && reports<3 && now-sent>TimeUnit.SECONDS.toNanos(8)) {
                reported=true;reports++;
                Path file=Path.of(System.getProperty("user.home"),".acas","diagnostics","ui-freeze-"+reports+".txt");
                Files.createDirectories(file.getParent());
                Files.writeString(file,threadDump());
                report.accept("ACAS: UI stalled for over 8 seconds. Thread diagnostic saved to "+file);
            }
        } catch(Exception error){reported=true;}
    }
    public static String threadDump(){
        StringBuilder text=new StringBuilder("ACAS UI stall diagnostic "+java.time.Instant.now()+"\n");
        var bean=ManagementFactory.getThreadMXBean();
        long[] deadlocked=bean.findDeadlockedThreads();
        text.append("Deadlocked thread IDs: ").append(java.util.Arrays.toString(deadlocked)).append('\n');
        var runtime=Runtime.getRuntime();
        text.append("Heap used/max: ").append(runtime.totalMemory()-runtime.freeMemory()).append('/').append(runtime.maxMemory()).append('\n');
        for(var info:bean.dumpAllThreads(true,true)) {
            text.append('\n').append(info.getThreadName()).append(" id=").append(info.getThreadId()).append(' ').append(info.getThreadState())
                .append(" waitingOn=").append(info.getLockName()).append(" owner=").append(info.getLockOwnerName()).append('\n');
            for(var frame:info.getStackTrace())text.append("  at ").append(frame).append('\n');
        }
        return text.toString();
    }
    public void close(){worker.shutdownNow();}
}
