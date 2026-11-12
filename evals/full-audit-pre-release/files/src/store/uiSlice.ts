import AsyncStorage from '@react-native-async-storage/async-storage';
import { createSlice } from '@reduxjs/toolkit';

const uiSlice = createSlice({ name: 'ui', initialState: { theme: 'light' }, reducers: {} });
export default uiSlice.reducer;

// Remember that the user closed the "sign in for faster checkout" banner.
export async function dismissAuthPrompt() {
  await AsyncStorage.setItem('authPromptDismissed', 'true');
}

export async function markOnboardingSeen() {
  await AsyncStorage.setItem('onboardingSeen', 'true');
}
