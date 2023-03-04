template Multiply() {
  signal input x;
  signal input y;
  signal output z;

  z <-- x * y
  z === x * y   // this means rank-1, which means one side it will be linear (z) and other side it will multiplication of 2 variables (x & y)
  // there should not be a 3rd variable multiplication like, z === x * x * y, this will give error.

  // OR to combine both lines

  z <== x * y
}

component main {public [x]} = Multiply();