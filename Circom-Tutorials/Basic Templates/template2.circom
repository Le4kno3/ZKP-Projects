template RepeatedSquaring(n){ // here "n" is template argument.
  signal input x;
  signal output y;

  // template variable is fixed at compile time

  // use of template variable - to declare an array of size `n`
  signal xs[n+1];

  xs[0] <== x;

  // use of template variable - for loops iteration
  for (var i=0; i<n; i++){
    // looped logic
    xs[i+1] <== xs[i] * xs[i]
  }

  // yes all the intermediate squares will be stored in xs[] array

  y <== xs[n];  //this will be the final output
}

component main {public [x]} = RepeatedSquaring(1000);