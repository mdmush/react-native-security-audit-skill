import React from 'react';
import { View } from 'react-native';

// Placeholder rows while products load. Widths are randomised so it looks natural.
export function SkeletonList({ rows = 6 }: { rows?: number }) {
  return (
    <View>
      {Array.from({ length: rows }).map((_, i) => (
        <View key={`skeleton-${i}-${Math.random()}`} style={{ height: 16, width: `${50 + Math.random() * 40}%` }} />
      ))}
    </View>
  );
}
