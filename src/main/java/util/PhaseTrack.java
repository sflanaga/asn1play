package util;

import static java.util.stream.Collectors.joining;
import static util.Util.convert;
import static util.Util.toSIAbbreviation;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;

@Slf4j
/// Track the times or phases of processing within a single thread
/// It is effectively a thread local object and good for situations
/// where bulk data in transferred to routines as phases of processing
/// not good for record at a time timing situations... well, not really
/// but it might be used that way - just wouldn't recommend it.
/// In such a situation the entries into the hashmap would likely
/// interfere with the performance of the thing you are measuring.
public class PhaseTrack {
  private static final ThreadLocal<PhaseTrackInternal> threadLocal = ThreadLocal.withInitial(
      PhaseTrackInternal::new);

  public static void start() {
    PhaseTrackInternal pt = threadLocal.get();
    pt.start();
  }

  public static void recordTimePoint(String name) {
    PhaseTrackInternal pt = threadLocal.get();
    pt.recordTimePoint(name);
  }

  public static void logTimes(String msg, Level logLevel, TimeUnit units) {
    PhaseTrackInternal pt = threadLocal.get();
    pt.logTimes(msg, logLevel, units);
  }

  public static long startToNowNanos() {
    PhaseTrackInternal pt = threadLocal.get();
    return System.nanoTime() - pt.startTime;
  }

  private static class PhaseTrackInternal {

    private long startTime;
    private long timePoint;
    private LinkedHashMap<String, Long> phases = new LinkedHashMap<>();

    private PhaseTrackInternal() {
      timePoint = System.nanoTime();
    }

    private void start() {
      timePoint = System.nanoTime();
      startTime = timePoint;
      phases.clear();
    }

    public void recordTimePoint(String name) {
      long lastTimePoint = timePoint;
      timePoint = System.nanoTime();
      long deltaTime = timePoint - lastTimePoint;
      phases.put(name, deltaTime);
    }

    public void logTimes(String msg, Level logLevel, TimeUnit units) {
      log.info("{}[{}] {}", msg, nanosToSi(System.nanoTime()-startTime, TimeUnit.MILLISECONDS),
          phases.entrySet().stream().map(e ->
          e.getKey() + "=" +
              nanosToSi(e.getValue(),units)).collect(joining(", ")));
      phases.clear();
    }
  }

  public static String nanosToSi(long nanos, TimeUnit units) {
    return convert(Duration.ofNanos(nanos), units) + toSIAbbreviation(units);
  }

  /// simple test driver to make sure the timing is tracked ok per thread
  public static void main(String[] args) {
    try {

      List<Thread> threadList = IntStream.range(0, 4).boxed().map(threadIdx -> {
        Thread t = new Thread() {
          @Override
          public void run() {
            try {
              while(true) {
                PhaseTrack.start();
                Thread.sleep(100L + 100 * threadIdx);
                PhaseTrack.recordTimePoint("hello 1st");
                Thread.sleep(100L + 100 * threadIdx);
                if ( threadIdx == 2)
                  PhaseTrack.start();
                PhaseTrack.recordTimePoint("hello 2nd");
                Thread.sleep(100L + 100 * threadIdx);
                PhaseTrack.recordTimePoint("hello 3rd");
                Thread.sleep(100L + 100 * threadIdx);
                PhaseTrack.recordTimePoint("hello rth");
                PhaseTrack.logTimes("Final: ", Level.INFO, TimeUnit.MILLISECONDS);
              }
            } catch (InterruptedException i) {
              i.printStackTrace();
            }
          }
        };
        t.setName("t: " + threadIdx);
        t.start();
        return t;
      }).collect(Collectors.toList());

      threadList.forEach(t->{try{t.join();}catch(Exception e) {}});


    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
