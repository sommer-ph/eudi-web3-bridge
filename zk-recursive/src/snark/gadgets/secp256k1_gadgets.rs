use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::gadgets::non_native_field::NonNativeFieldTarget;
use plonky2::iop::target::Target;

use crate::snark::gadgets::secp256k1_point_target::Secp256k1PointTarget;
use crate::snark::fields::secp256k1_base::Secp256K1Base;

pub trait Secp256k1Gadgets<F: Field, const D: usize> {
    fn secp256k1_curve_add(
        &mut self,
        p1: Secp256k1PointTarget<F>,
        p2: Secp256k1PointTarget<F>,
    ) -> Secp256k1PointTarget<F>;

    fn secp256k1_curve_double(
        &mut self,
        p: Secp256k1PointTarget<F>,
    ) -> Secp256k1PointTarget<F>;

    fn secp256k1_scalar_mul(
        &mut self,
        point: Secp256k1PointTarget<F>,
        scalar: Target,
    ) -> Secp256k1PointTarget<F>;

    fn infinity_point(&mut self) -> Secp256k1PointTarget<F>;
}

impl<F: Field + Extendable<D>, const D: usize> Secp256k1Gadgets<F, D> for CircuitBuilder<F, D> {
    fn secp256k1_curve_add(
        &mut self,
        p1: Secp256k1PointTarget<F>,
        p2: Secp256k1PointTarget<F>,
    ) -> Secp256k1PointTarget<F> {
        // Case 1: One of the points is ∞
        let either_inf = self.or(p1.is_infinity, p2.is_infinity);

        // Case 2: x1 == x2 && y1 == -y2 → results in ∞
        let x_eq = self.non_native_eq(&p1.x, &p2.x);
        let y_neg = self.neg_non_native(p2.y.clone());
        let y_is_neg = self.non_native_eq(&p1.y, &y_neg);
        let inverse_case = self.and(x_eq, y_is_neg);

        // We set is_infinity if:
        // - one is ∞ → handled above by select
        // - the points are additive inverses
        let should_be_inf = self.or(either_inf, inverse_case);

        // Normal lambda calculation
        let x_diff = self.sub_non_native(p2.x.clone(), p1.x.clone());
        let y_diff = self.sub_non_native(p2.y.clone(), p1.y.clone());
        let x_diff_inv = self.inv_non_native(x_diff);
        let lambda = self.mul_non_native(y_diff, x_diff_inv);

        let lambda_sq = self.square_non_native(lambda.clone());
        let x3 = self.sub_non_native(
            self.sub_non_native(lambda_sq, p1.x.clone()),
            p2.x.clone(),
        );

        let x1_minus_x3 = self.sub_non_native(p1.x.clone(), x3.clone());
        let lambda_times = self.mul_non_native(lambda, x1_minus_x3);
        let y3 = self.sub_non_native(lambda_times, p1.y.clone());

        // Raw point without infinity handling
        let raw = Secp256k1PointTarget {
            x: x3,
            y: y3,
            is_infinity: self._false(),
        };

        // Return ∞ if necessary
        self.select_point(
            self.infinity_point(),
            raw,
            should_be_inf,
        )
    }

    fn secp256k1_curve_double(
        &mut self,
        p: Secp256k1PointTarget<F>,
    ) -> Secp256k1PointTarget<F> {
        // If y == 0 → ∞
        let y_is_zero = self.non_native_is_zero(&p.y);

        let x_sq = self.square_non_native(p.x.clone());
        let three = Secp256K1Base::from_canonical_u64(3);
        let three_x_sq = self.mul_const_non_native(three, x_sq);

        let two = Secp256K1Base::from_canonical_u64(2);
        let two_y = self.mul_const_non_native(two, p.y.clone());

        let lambda = self.div_non_native(three_x_sq.clone(), two_y);
        let lambda_sq = self.square_non_native(lambda.clone());
        let two_x = self.mul_const_non_native(two, p.x.clone());
        let x3 = self.sub_non_native(lambda_sq, two_x);

        let x_minus_x3 = self.sub_non_native(p.x.clone(), x3.clone());
        let lambda_times = self.mul_non_native(lambda, x_minus_x3);
        let y3 = self.sub_non_native(lambda_times, p.y.clone());

        let raw = Secp256k1PointTarget {
            x: x3,
            y: y3,
            is_infinity: self._false(),
        };

        self.select_point(self.infinity_point(), raw, y_is_zero)
    }

    fn secp256k1_scalar_mul(
        &mut self,
        point: Secp256k1PointTarget<F>,
        scalar: Target,
    ) -> Secp256k1PointTarget<F> {
        let bits_le = self.split_le(scalar, 64);

        let mut acc = Secp256k1PointTarget {
            x: self.zero_non_native(),
            y: self.zero_non_native(),
            is_infinity: self._true(),
        };

        for &bit in bits_le.iter().rev() {
            acc = self.secp256k1_curve_double(acc);
            let sum = self.secp256k1_curve_add(acc.clone(), point.clone());
            acc = self.select_point(sum, acc, bit);
        }

        acc
}

    fn infinity_point(&mut self) -> Secp256k1PointTarget<F> {
        Secp256k1PointTarget {
            x: self.zero_non_native(),
            y: self.zero_non_native(),
            is_infinity: self._true(),
        }
    }

}
