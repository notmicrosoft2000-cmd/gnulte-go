package ux

import "testing"

func TestSparkRTTLevels(t *testing.T) {
	samples := []int{-1, 4, 12, 64, 300, 600}
	got := SparkRTT(samples, 10)
	want := "·▁▂▅▇█"
	if got != want {
		t.Fatalf("SparkRTT = %q, want %q", got, want)
	}
}

func TestSparkRTTWidthCap(t *testing.T) {
	samples := make([]int, 100)
	for i := range samples {
		samples[i] = 10
	}
	got := SparkRTT(samples, 30)
	if len([]rune(got)) != 30 {
		t.Fatalf("SparkRTT width = %d, want 30 (all levels are single-cell runes)", len([]rune(got)))
	}
}

func TestSparkRTTEmpty(t *testing.T) {
	if SparkRTT(nil, 30) != "" || SparkRTT([]int{}, 0) != "" {
		t.Fatal("SparkRTT should return empty for no samples or zero width")
	}
}
