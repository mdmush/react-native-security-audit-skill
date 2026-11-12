import React from 'react';
import { Button, Text, View } from 'react-native';
import { useSelector } from 'react-redux';
import { api } from '../api/client';
import type { RootState } from '../store';

export default function OrderDetailScreen({ route }: any) {
  const user = useSelector((s: RootState) => s.auth.user);
  const { orderId } = route.params;

  return (
    <View>
      <Text>Order {orderId}</Text>
      {user?.isAdmin && (
        <Button title="Cancel order for customer" onPress={() => api.post(`/admin/orders/${orderId}/cancel`)} />
      )}
    </View>
  );
}
