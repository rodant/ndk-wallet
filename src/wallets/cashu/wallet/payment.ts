import {
    CashuPaymentInfo,
    LnPaymentInfo,
    NDKPaymentConfirmationCashu,
    NDKZapDetails,
    NDKEvent,
    NDKUser,
    NDKTag,
    NDKPaymentConfirmationLN,
} from "@nostr-dev-kit/ndk";
import { NDKCashuWallet } from ".";
import { createToken } from "../pay/nut";
import { payLn } from "../pay/ln";
import { getBolt11Amount } from "../../../utils/ln";
import { createOutTxEvent } from "./txs";

export type PaymentWithOptionalZapInfo<T extends LnPaymentInfo | CashuPaymentInfo> = T & {
    target?: NDKEvent | NDKUser;
    comment?: string;
    tags?: NDKTag[];
    amount?: number;
    unit?: string;
    recipientPubkey?: string;
    paymentDescription?: string;
};

export class PaymentHandler {
    private wallet: NDKCashuWallet;

    constructor(wallet: NDKCashuWallet) {
        this.wallet = wallet;
    }

    /**
     * Pay a LN invoice with this wallet. This will used cashu proofs to pay a bolt11.
     */
    async lnPay(
        payment: PaymentWithOptionalZapInfo<LnPaymentInfo>,
        createTxEvent = true
    ): Promise<NDKPaymentConfirmationLN | undefined> {
        if (!payment.pr) throw new Error("pr is required");

        const invoiceAmount = getBolt11Amount(payment.pr);
        if (!invoiceAmount) throw new Error("invoice amount is required");

        // if amount was passed in, we want to check that the invoice amount is not more than it
        if (payment.amount && invoiceAmount > payment.amount) {
            throw new Error("invoice amount is more than the amount passed in");
        }

        const res = await payLn(this.wallet, payment.pr, {
            amount: payment.amount,
            unit: payment.unit,
        }); // msat to sat
        if (!res?.result?.preimage) return;

        if (createTxEvent) {
            createOutTxEvent(this.wallet.ndk, payment, res, this.wallet.relaySet);
        }

        return res.result;
    }

    /**
     * Swaps tokens to a specific amount, optionally locking to a p2pk.
     */
    async cashuPay(
        payment: NDKZapDetails<CashuPaymentInfo>,
        p2pk?: {
            pubkey: string | string[];
            locktime?: number;
            refundKeys?: string[];
            requiredSignatures?: number;
            requiredRefundSignatures?: number;
            additionalTags?: Array<[key: string, ...values: string[]]>;
        }
    ): Promise<NDKPaymentConfirmationCashu | undefined> {
        const satPayment = { ...payment };
        if (satPayment.unit?.startsWith("msat")) {
            satPayment.amount = satPayment.amount / 1000;
            satPayment.unit = "sat";
        }

        const p2pkOps = p2pk ? { ...p2pk } : { pubkey: payment.recipientPubkey };
        if (Array.isArray(p2pkOps?.pubkey)) {
            p2pkOps.pubkey.push(payment.recipientPubkey);
            p2pkOps.pubkey.reverse();
        } else if (p2pkOps?.pubkey && payment.recipientPubkey !== p2pkOps.pubkey) {
            p2pkOps.pubkey = [payment.recipientPubkey, p2pkOps.pubkey];
        } else {
            p2pkOps.pubkey = [payment.recipientPubkey];
        }

        let createResult = await createToken(
            this.wallet,
            satPayment.amount,
            payment.mints,
            p2pkOps
        );
        // If Token was created with Mint Transfer, the Token Minted Needs to be saved!
        if (!createResult) {
            if (payment.allowIntramintFallback) {
                createResult = await createToken(
                    this.wallet,
                    satPayment.amount,
                    undefined,
                    p2pkOps
                );
            }

            if (!createResult) {
                return;
            }
        }

        createOutTxEvent(this.wallet.ndk, satPayment, createResult, this.wallet.relaySet, undefined, p2pk);

        return createResult.result;
    }
}
