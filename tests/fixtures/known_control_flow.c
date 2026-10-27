#include <stdio.h>

// 1. Arithmetic & memory operations
int arithmetic_mem(int a, int b) {
    volatile int arr[4];
    arr[0] = a + b;
    arr[1] = a * b;
    arr[2] = arr[0] - arr[1];
    arr[3] = (b != 0) ? (a / b) : 0;
    return arr[2] + arr[3];
}

// 2. Direct and indirect calls
int target_add(int x) { return x + 10; }
int target_sub(int x) { return x - 5; }

int call_dispatch(int (*fn)(int), int val) {
    if (fn) {
        return fn(val);
    }
    return target_add(val);
}

// 3. Switch statements & jump table
int switch_jump_table(int key) {
    switch (key) {
        case 1: return 100;
        case 2: return 200;
        case 3: return 300;
        case 4: return 400;
        case 5: return 500;
        default: return -1;
    }
}

// 4. Tail call
int tail_helper(int n, int acc) {
    if (n <= 0) return acc;
    return tail_helper(n - 1, acc + n);
}

int tail_call_entry(int n) {
    return tail_helper(n, 0);
}

int main(int argc, char **argv) {
    int v = arithmetic_mem(argc, 5);
    int s = switch_jump_table(argc);
    int c = call_dispatch(target_sub, v);
    int t = tail_call_entry(argc);
    return v + s + c + t;
}
