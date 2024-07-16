use num_bigint::BigUint;

pub fn big_pow_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let one: BigUint = BigUint::from(1usize);
    let two: BigUint = BigUint::from(2usize);

    match b == &BigUint::default() {
        true => one,
        false => {
            let is_odd = b % &two == one;
            let b = if is_odd { b - one } else { b.clone() };
            let x = big_pow_mod(a, &(&b / &two), n);
            let x2 = (&x * &x) % n;

            if is_odd {
                (a * &x2) % n
            } else {
                x2
            }
        }
    }
}
