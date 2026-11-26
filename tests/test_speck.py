from security_seti.ciphers.speck import Speck32, speck32_encrypt, key_schedule


def test_speck32_known_vector():
    # Standard SPECK32/64 test vector (22 rounds):
    # key = 1918 1110 0908 0100, pt = 6574 694c, ct = a868 42f2
    key = [0x0100, 0x0908, 0x1110, 0x1918]  # K0 least significant
    x, y = speck32_encrypt(key, 0x6574, 0x694c, rounds=22)
    assert (x, y) == (0xA868, 0x42F2)


def test_key_schedule_length():
    key = [0x0100, 0x0908, 0x1110, 0x1918]
    assert len(key_schedule(key, rounds=22)) == 22
    assert len(key_schedule(key, rounds=5)) == 5


def test_reduced_rounds_differs_from_full():
    key = [0x0100, 0x0908, 0x1110, 0x1918]
    assert speck32_encrypt(key, 0x6574, 0x694c, rounds=3) != (0xA868, 0x42F2)


def test_block_api_matches_word_api():
    key = [1, 2, 3, 4]
    c = Speck32(key, rounds=10)
    x, y = c.encrypt(0x1234, 0x5678)
    assert c.encrypt_block(0x12345678) == (x << 16) | y
