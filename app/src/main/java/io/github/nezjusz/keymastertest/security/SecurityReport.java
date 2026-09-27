package io.github.nezjusz.keymastertest.security;

import java.util.ArrayList;
import java.util.List;

/** Outcome of the security probes, ready for display. */
public final class SecurityReport {

    public enum Status {
        GOOD,
        WARNING,
        BAD,
        UNKNOWN
    }

    public static final class Signal {
        public final String label;
        public final Status status;
        public final String value;

        public Signal(String label, Status status, String value) {
            this.label = label;
            this.status = status;
            this.value = value;
        }
    }

    public enum Trust {
        /** Hardware keystore, attested, locked, verified boot, locked bootloader. */
        STRONG,
        /** Signals are mixed or incomplete; nothing conclusively failed. */
        PARTIAL,
        /** At least one signal is conclusively bad. */
        COMPROMISED,
        /** Not enough could be gathered to say anything. */
        UNDETERMINED
    }

    public final List<Signal> signals;
    public final Trust trust;
    public final String trustHeadline;
    public final String trustExplanation;
    public final List<String> trustReasons;
    /** Full diagnosis and raw exception chains, behind the result card's "Show full error". */
    public final String detail;

    public SecurityReport(List<Signal> signals, Trust trust, String trustHeadline,
                          String trustExplanation, List<String> trustReasons) {
        this(signals, trust, trustHeadline, trustExplanation, trustReasons, null);
    }

    public SecurityReport(List<Signal> signals, Trust trust, String trustHeadline,
                          String trustExplanation, List<String> trustReasons, String detail) {
        this.signals = signals;
        this.trust = trust;
        this.trustHeadline = trustHeadline;
        this.trustExplanation = trustExplanation;
        this.trustReasons = trustReasons == null ? new ArrayList<>() : trustReasons;
        this.detail = detail;
    }
}
