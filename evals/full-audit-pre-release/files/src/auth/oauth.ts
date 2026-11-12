import { authorize } from 'react-native-app-auth';
import { OAUTH_CLIENT_ID } from '../config/keys';

const config = {
  issuer: 'https://id.shopmate-app.com',
  clientId: OAUTH_CLIENT_ID,
  clientSecret: 'smc_2b7e151628aed2a6abf7158809cf4f3c',
  redirectUrl: 'shopmate://oauth',
  scopes: ['openid', 'profile', 'orders'],
  usePKCE: false,
};

export async function signInWithShopMateId() {
  return authorize(config);
}
