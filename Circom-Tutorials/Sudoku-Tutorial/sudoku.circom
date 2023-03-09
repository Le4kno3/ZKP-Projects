pragma circom 2.0.0;

template NonEqual(){
    signal input in0;
    signal input in1;
    signal inv;
    inv <-- 1/ (in0 - in1);
    inv*(in0 - in1) === 1;
}

// check if all elements are unique in an array
template Distinct(n) {
    signal input in[n];
    component nonEqual[n][n];   //array of components, where each cell in this 2D arraw stores a `NonEqual()` component.
    for(var i = 0; i < n; i++){
        for(var j = 0; j < i; j++){
            nonEqual[i][j] = NonEqual();    // this is how the component is set
            nonEqual[i][j].in0 <== in[i];   // setting arguments of the component
            nonEqual[i][j].in1 <== in[j];   // setting arguments of the component
        }
    }
}

// Enforce that 0 <= in < 16
template Bits4(){
    signal input in;
    signal bits[4];
    var bitsum = 0;
    for (var i = 0; i < 4; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        bitsum = bitsum + 2 ** i * bits[i];
    }
    bitsum === in;
}

// Enforce that 1 <= in <= 9
template OneToNine() {
    signal input in;
    component lowerBound = Bits4();     // all will be 0 <= in < 16
    component upperBound = Bits4();     // all will be 0 <= in < 16

    //
    lowerBound.in <== in - 1;
    upperBound.in <== in + 6;
}

template Sudoku(n) {
    // w: input, solution is a 2D array which is the final solution of the sudoku: indices are (row_i, col_i)
    signal input solution[n][n];

    // x: input, puzzle is the same, which is the problem that the user needs to solve, but a zero indicates a blank
    signal input puzzle[n][n];

    component distinct[n];
    component inRange[n][n];

    // just a simple check to verify that the solution has all values filled that are left blank in puzzle.
    // this by no means verifies the validity of the solution
    for (var row_i = 0; row_i < n; row_i++) {
        for (var col_i = 0; col_i < n; col_i++) {
            // we could make this a component
            // the 2nd operand will be zero if puzzle[row_i][col_i] has value
            // the 1st operand will be zero if puzzle[row_i][col_i] has 0 as value.
            puzzle[row_i][col_i] * (puzzle[row_i][col_i] - solution[row_i][col_i]) === 0;
        }
    }

    // 
    for (var row_i = 0; row_i < n; row_i++) {
        for (var col_i = 0; col_i < n; col_i++) {

            // for every new column, we create a new instance of `Distince` to check distince for all columns
            if (row_i == 0) {
                distinct[col_i] = Distinct(n);
            }
            //instantiate inRange[][] for the particular cell checking
            inRange[row_i][col_i] = OneToNine();
            
            // set the value of the particular cell to check if that cell value is inbetween 1-9.
            // As the OneToNine only needs one input, this will also run the template.
            inRange[row_i][col_i].in <== solution[row_i][col_i];

            // this will check each cell for both rows and columns if both rows are distince and columns are distinct.
            // As the Distince(n) only needs one input with argument, this will also run the template.
            distinct[col_i].in[row_i] <== solution[row_i][col_i];

            //What the output the?
            // If everything runs successfully without throwing any error, then all good, as circom is an assertion based HDL language.
        }
    }
}

component main {public[puzzle]} = Sudoku(9);

