package io.github.nezjusz.keymastertest.security;

import java.util.Arrays;

/**
 * Minimal DER reader, just enough to walk the Android key attestation extension.
 *
 * <p>This exists to avoid pulling a full ASN.1 provider (and its several megabytes) into the
 * app for the sake of reading a few hundred bytes of a certificate extension. It handles the
 * tag, length, and value forms that structure actually uses, including the high-tag-number
 * form needed for the AuthorizationList tags above 30.
 */
final class Der {

    static final int TAG_BOOLEAN = 0x01;
    static final int TAG_INTEGER = 0x02;
    static final int TAG_BIT_STRING = 0x03;
    static final int TAG_OCTET_STRING = 0x04;
    static final int TAG_NULL = 0x05;
    static final int TAG_OID = 0x06;
    static final int TAG_ENUMERATED = 0x0A;
    static final int TAG_SEQUENCE = 0x10;
    static final int TAG_SET = 0x11;

    private final byte[] data;
    private final int end;
    private int pos;

    Der(byte[] data) {
        this(data, 0, data.length);
    }

    Der(byte[] data, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException("DER: range out of bounds");
        }
        this.data = data;
        this.pos = offset;
        this.end = offset + length;
    }

    boolean hasMore() {
        return pos < end;
    }

    /** Reads the next tag-length-value and advances past it. */
    Tlv next() {
        if (!hasMore()) {
            throw new IllegalStateException("DER: unexpected end of data");
        }
        int identifier = data[pos++] & 0xFF;
        boolean constructed = (identifier & 0x20) != 0;
        int tagNumber = identifier & 0x1F;
        if (tagNumber == 0x1F) {
            tagNumber = 0;
            int b = data[pos++] & 0xFF;
            tagNumber = b & 0x7F;
            while ((b & 0x80) != 0) {
                if (!hasMore()) {
                    throw new IllegalStateException("DER: truncated tag");
                }
                b = data[pos++] & 0xFF;
                tagNumber = (tagNumber << 7) | (b & 0x7F);
            }
        }

        int length = readLength();
        if (length < 0 || pos + length > end) {
            throw new IllegalStateException("DER: value overruns buffer");
        }
        Tlv tlv = new Tlv(tagNumber, constructed, data, pos, length);
        pos += length;
        return tlv;
    }

    private int readLength() {
        if (!hasMore()) {
            throw new IllegalStateException("DER: truncated length");
        }
        int b = data[pos++] & 0xFF;
        if ((b & 0x80) == 0) {
            return b;
        }
        int count = b & 0x7F;
        if (count == 0) {
            throw new IllegalStateException("DER: indefinite length not supported");
        }
        if (count > 4) {
            throw new IllegalStateException("DER: length too large");
        }
        int length = 0;
        for (int i = 0; i < count; i++) {
            if (!hasMore()) {
                throw new IllegalStateException("DER: truncated length");
            }
            length = (length << 8) | (data[pos++] & 0xFF);
        }
        return length;
    }

    static final class Tlv {
        final int tagNumber;
        final boolean constructed;
        private final byte[] buffer;
        private final int offset;
        private final int length;

        Tlv(int tagNumber, boolean constructed, byte[] buffer, int offset, int length) {
            this.tagNumber = tagNumber;
            this.constructed = constructed;
            this.buffer = buffer;
            this.offset = offset;
            this.length = length;
        }

        byte[] value() {
            return Arrays.copyOfRange(buffer, offset, offset + length);
        }

        /** A reader over this value, for descending into constructed elements. */
        Der content() {
            return new Der(buffer, offset, length);
        }

        int asInt() {
            if (length == 0) {
                return 0;
            }
            int result = 0;
            for (int i = 0; i < length; i++) {
                result = (result << 8) | (buffer[offset + i] & 0xFF);
            }
            return result;
        }

        boolean asBoolean() {
            return length > 0 && buffer[offset] != 0;
        }
    }
}
