package de.gematik.vau.lib.data;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class EncryptionVauKeyTest {

    private static final byte[] EXPECTED_BYTES_AFTER_INITIALIZATION = new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static final byte[] EXPECTED_BYTES_AFTER_ONE_COUNT_UP = new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    private static final byte[] EXPECTED_BYTES_AFTER_257_COUNT_UPS = new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01
    };

    @Test
    void hasExpectedByteRepresentationAfterInitialization() {
        EncryptionVauKey encryptionVauKey = new EncryptionVauKey(new byte[]{});
        byte[] actualCounter = encryptionVauKey.getCounter();

        assertArrayEquals(EXPECTED_BYTES_AFTER_INITIALIZATION, actualCounter);
    }

    @Test
    void hasExpectedByteRepresentationAfterOneCountUp() {
        EncryptionVauKey encryptionVauKey = new EncryptionVauKey(new byte[]{});
        encryptionVauKey.countUp();
        byte[] actualCounter = encryptionVauKey.getCounter();

        assertArrayEquals(EXPECTED_BYTES_AFTER_ONE_COUNT_UP, actualCounter);
    }

    @Test
    void hasExpectedByteRepresentationAfter257CountUps() {
        EncryptionVauKey encryptionVauKey = new EncryptionVauKey(new byte[]{});
        for (int i = 0; i < 257; i++) {
            encryptionVauKey.countUp();
        }
        byte[] actualCounter = encryptionVauKey.getCounter();

        assertArrayEquals(EXPECTED_BYTES_AFTER_257_COUNT_UPS, actualCounter);
    }

}