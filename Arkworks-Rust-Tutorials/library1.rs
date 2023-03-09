fn and(cs: ContraintSystem, a: Var, b:Var) -> Var {
  let result = cs.new_witness_var(|| a.value() & b.value());

  // checks if a x b = result
  self.cs.enforce_contraint(
    lc!() + a,
    lc!() + b,
    lc!() + result,
  );
  result
}