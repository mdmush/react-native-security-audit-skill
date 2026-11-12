import axios from 'axios';
import { PAYMENTS_API_SECRET } from '../config/keys';

const paybridge = axios.create({
  baseURL: 'https://api.paybridge.io/v2',
  headers: { Authorization: `Bearer ${PAYMENTS_API_SECRET}` },
});

// Called from the order detail screen when support staff tap "Refund".
export async function refundOrder(chargeId: string, amountCents: number) {
  const res = await paybridge.post('/refunds', { charge: chargeId, amount: amountCents });
  return res.data;
}

export async function listPayouts() {
  const res = await paybridge.get('/payouts');
  return res.data;
}
