package com.github.h3yow.zerotrustgatewayjava.replay;

/**
 * nonce/序号提交的原子结果。
 */
public enum ReplayResult {
    /** 首次出现且序号前进：接受。 */
    ACCEPTED,
    /** nonce 在有效期内重复。 */
    DUPLICATE_NONCE,
    /** 序号未前进（回退或相等）。 */
    SEQUENCE_ROLLBACK
}
