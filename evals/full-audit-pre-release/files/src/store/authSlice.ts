import { createSlice, PayloadAction } from '@reduxjs/toolkit';

type AuthState = {
  accessToken: string | null;
  refreshToken: string | null; // 90-day lifetime, rotates on use
  user: { id: string; email: string; isAdmin: boolean } | null;
};

const initialState: AuthState = { accessToken: null, refreshToken: null, user: null };

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    signedIn(state, action: PayloadAction<AuthState>) {
      return action.payload;
    },
    signedOut() {
      return initialState;
    },
  },
});

export const { signedIn, signedOut } = authSlice.actions;
export default authSlice.reducer;
