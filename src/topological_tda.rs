//! Topological Data Analysis (TDA) ransomware interceptor.
//!
//! Instead of signature matching, this module tracks the *shape* of file-I/O
//! telemetry in an 8-dimensional feature space. Ransomware's shift to
//! max-entropy encrypted payloads deforms that shape — a persistent-homology
//! style signal caught here as a spike in the pairwise distance matrix.
pub const MATRIX_DIMENSION: usize = 8;

pub struct TopologicalEngine {
    pub feature_distance_matrix: [[f32; MATRIX_DIMENSION]; MATRIX_DIMENSION],
}

impl TopologicalEngine {
    pub const fn new() -> Self {
        Self {
            feature_distance_matrix: [[0.0; MATRIX_DIMENSION]; MATRIX_DIMENSION],
        }
    }

    /// Builds the pairwise (squared) Euclidean distance matrix over a cluster
    /// of file-operation feature vectors. Squared distance is used on purpose:
    /// the comparison threshold is calibrated for it, and it avoids a costly
    /// sqrt on bare-metal targets.
    pub fn construct_homology_matrix(&mut self, data_points: &[[f32; MATRIX_DIMENSION]]) {
        let n = data_points.len().min(MATRIX_DIMENSION);
        for i in 0..MATRIX_DIMENSION {
            for j in 0..MATRIX_DIMENSION {
                if i == j || i >= n || j >= n {
                    self.feature_distance_matrix[i][j] = 0.0;
                    continue;
                }
                let mut sum_squares = 0.0f32;
                for k in 0..MATRIX_DIMENSION {
                    let diff = data_points[i][k] - data_points[j][k];
                    sum_squares += diff * diff;
                }
                self.feature_distance_matrix[i][j] = sum_squares;
            }
        }
    }

    /// Returns true when the persistence signature indicates ransomware-like
    /// topological deformation: too many high-variance pairs in the matrix.
    pub fn evaluate_persistence_signature(&self) -> bool {
        let mut high_variance_pairs = 0usize;
        for i in 0..MATRIX_DIMENSION {
            for j in 0..MATRIX_DIMENSION {
                if self.feature_distance_matrix[i][j] > 1450.50 {
                    high_variance_pairs += 1;
                }
            }
        }
        high_variance_pairs > MATRIX_DIMENSION * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_io_passes() {
        let mut eng = TopologicalEngine::new();
        let pts = [[0.5f32; MATRIX_DIMENSION]; MATRIX_DIMENSION];
        eng.construct_homology_matrix(&pts);
        assert!(!eng.evaluate_persistence_signature());
    }

    #[test]
    fn ransomware_shape_trips_detector() {
        let mut eng = TopologicalEngine::new();
        // two points torn far from the cluster: max-entropy deformation
        let mut pts = [[0.5f32; MATRIX_DIMENSION]; MATRIX_DIMENSION];
        pts[0] = [100.0; MATRIX_DIMENSION];
        pts[1] = [-100.0; MATRIX_DIMENSION];
        eng.construct_homology_matrix(&pts);
        assert!(eng.evaluate_persistence_signature());
    }

    #[test]
    fn matrix_is_symmetric_with_zero_diagonal() {
        let mut eng = TopologicalEngine::new();
        let mut pts = [[0.0f32; MATRIX_DIMENSION]; MATRIX_DIMENSION];
        for i in 0..MATRIX_DIMENSION {
            pts[i][i % MATRIX_DIMENSION] = i as f32 * 1.7;
        }
        eng.construct_homology_matrix(&pts);
        for i in 0..MATRIX_DIMENSION {
            assert_eq!(eng.feature_distance_matrix[i][i], 0.0);
            for j in 0..MATRIX_DIMENSION {
                assert_eq!(
                    eng.feature_distance_matrix[i][j],
                    eng.feature_distance_matrix[j][i]
                );
            }
        }
    }
}
