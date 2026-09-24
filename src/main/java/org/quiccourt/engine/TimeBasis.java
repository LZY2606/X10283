package org.quiccourt.engine;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 时间坐标基准。所有规范化时间为 epoch 微秒（µs since Unix epoch）。
 * 无法转换的原始表示留在原位置并附诊断（parse 返回 null + diagnostic）。
 */
public final class TimeBasis {
    private TimeBasis() {}

    private static final Pattern US = Pattern.compile("\\s*(-?\\d+)\\s*(us|µs)\\s*", Pattern.CASE_INSENSITIVE);
    private static final Pattern MS = Pattern.compile("\\s*(-?\\d+)\\s*ms\\s*", Pattern.CASE_INSENSITIVE);
    private static final Pattern SEC = Pattern.compile("\\s*(-?\\d+(?:\\.\\d+)?)\\s*s\\s*", Pattern.CASE_INSENSITIVE);

    public record Parsed(long epochUs, String basis) {}

    /** @return null 表示无法转换（调用方保留原值并记录诊断）。 */
    public static Parsed parse(String raw) {
        if (raw == null) return null;
        Matcher m;
        if ((m = US.matcher(raw)).matches()) return new Parsed(Long.parseLong(m.group(1)), "epoch-us");
        if ((m = MS.matcher(raw)).matches()) return new Parsed(Long.parseLong(m.group(1)) * 1_000L, "epoch-ms->us");
        if ((m = SEC.matcher(raw)).matches()) {
            double v = Double.parseDouble(m.group(1));
            return new Parsed((long) (v * 1_000_000L), "epoch-s->us");
        }
        if (raw.trim().matches("-?\\d+")) return new Parsed(Long.parseLong(raw.trim()), "epoch-us");
        return null;
    }
}
