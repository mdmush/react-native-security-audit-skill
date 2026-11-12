import { createSlice } from '@reduxjs/toolkit';

const cartSlice = createSlice({
  name: 'cart',
  initialState: { items: [] as { sku: string; qty: number }[] },
  reducers: {
    added(state, action) {
      state.items.push(action.payload);
    },
  },
});

export default cartSlice.reducer;
