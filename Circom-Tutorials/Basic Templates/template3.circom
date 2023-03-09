template NonZero(){
  signal input in;
  signal inverse;
  inverse <-- 1 / in;   // not R1CS

  // checks if `in` is non-zero
  1 === in * inverse;   // is R1CS
}

template Main() {
  signal input a;
  signal input b;

  component nz = NonZero();
  nz.in <== a;
  0 === a * b;  // this asserts indirectly that b == 0
}