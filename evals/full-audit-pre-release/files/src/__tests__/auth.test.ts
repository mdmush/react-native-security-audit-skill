import AsyncStorage from '@react-native-async-storage/async-storage';

const fakeToken = 'test-token-1234567890abcdef';

describe('auth storage', () => {
  it('round-trips a token in the mock', async () => {
    await AsyncStorage.setItem('token', fakeToken);
    expect(await AsyncStorage.getItem('token')).toBe(fakeToken);
  });
});
