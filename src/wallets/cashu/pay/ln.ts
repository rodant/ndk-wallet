import { MeltQuoteState } from "@cashu/cashu-ts";
import { NDKCashuWallet } from "../wallet/index.js";
import { getBolt11Amount } from "../../../utils/ln.js";
import { WalletOperation, withProofReserve } from "../wallet/effect.js";
import { calculateFee } from "../wallet/fee.js";
import { NDKPaymentConfirmationLN } from "@nostr-dev-kit/ndk";
import { consolidateMintTokens } from "../validate.js";
import type { MeltProofsResponse } from "@cashu/cashu-ts";

/**
 * Pay a Lightning Network invoice with a Cashu wallet.
 *
 * @param wallet - The Cashu wallet to use for the payment.
 * @param pr - The Lightning Network payment request (invoice) to pay.
 * @param { amount, unit } - The intended amount and unit to pay. -- Intended amount could be what we wanted to pay and the amount in the bolt11 might have a fee.
 * @returns A Promise that resolves to the payment preimage as a string if successful, or null if the payment fails.
 */
export async function payLn(
    wallet: NDKCashuWallet,
    pr: string,
    { amount, unit }: { amount?: number; unit?: string } = {}
): Promise<WalletOperation<NDKPaymentConfirmationLN> | null> {
    let invoiceAmount = getBolt11Amount(pr);
    if (!invoiceAmount) throw new Error("invoice amount is required");

    invoiceAmount = invoiceAmount / 1000; // msat

    if (amount && unit) {
        if (unit === "msat") {
            amount = amount / 1000;
        }
    }

    // we add three sats to the calculation as a guess for the fee
    const eligibleMints = wallet.getMintsWithBalance(invoiceAmount + 3);

    if (!eligibleMints.length) {
        return null;
    }

    for (const mint of eligibleMints) {
        try {
            const result = await executePayment(mint, pr, amount ?? invoiceAmount, wallet);
            if (result) {
                if (amount) {
                    result.fee = calculateFee(
                        amount,
                        result.proofsChange?.destroy ?? [],
                        result.proofsChange?.store ?? []
                    );
                }
                return result;
            }
        } catch (error: any) {
            console.log("Failed to execute payment for mint %s: %s", mint, error);
            wallet.warn(`Failed to execute payment with min ${mint}: ${error}`);
        }
    }

    return null;
}

/**
 * Attempts to pay using a selected set of Cashu tokens.
 *
 * @param selection - The TokenSelection object containing the chosen proofs and quote for the payment.
 * @param pr - The Lightning Network payment request (invoice) to pay.
 * @param wallet - The NDKCashuPay wallet instance.
 * @param debug - The debug function for logging.
 * @returns A Promise that resolves to the payment preimage as a string if successful, or null if the payment fails.
 *
 * @throws Will throw an error if the payment fails due to network issues or other problems.
 *
 * This function performs the following steps:
 * 1. Creates a new CashuWallet instance for the specific mint.
 * 2. Attempts to pay the Lightning invoice using the selected proofs.
 * 3. If successful, it rolls over any change proofs.
 * 4. If the proofs are already spent, it rolls over the selection without change.
 * 5. Logs the process and any errors for debugging purposes.
 */
async function executePayment(
    mint: string,
    pr: string,
    amountWithoutFees: number,
    wallet: NDKCashuWallet
): Promise<WalletOperation<NDKPaymentConfirmationLN> | null> {
    const cashuWallet = await wallet.getCashuWallet(mint, wallet.bip39seed);

    try {
        const meltQuote = await cashuWallet.createMeltQuote(pr);
        const amountToSend = meltQuote.amount + meltQuote.fee_reserve;

        const result = await withProofReserve<NDKPaymentConfirmationLN>(
            wallet,
            cashuWallet,
            mint,
            amountToSend,
            amountWithoutFees,
            async (proofsToUse, allOurProofs) => {
                const counterEntry = await wallet.state.getCounterEntryFor(cashuWallet.mint);
                const counter = wallet.bip39seed ? counterEntry.counter ?? 0 : undefined;
                const totalInputAmount = proofsToUse.reduce((sum, proof) => sum + proof.amount, 0);
                const changeAmount = totalInputAmount - meltQuote.amount;
                let blankOutputsCount = 0;
                if (changeAmount > 0) {
                    blankOutputsCount = Math.ceil(Math.log2(changeAmount)) || 1;
                }
                if (wallet.bip39seed && blankOutputsCount > 0) {
                    await wallet.incrementDeterministicCounter(
                        counterEntry.counterKey,
                        blankOutputsCount
                    );
                }

                let meltResult: MeltProofsResponse;
                try {
                    meltResult = await cashuWallet.meltProofs(meltQuote, proofsToUse, { counter });
                } catch (error: any) {
                    const errorMessage = error instanceof Error ? error.message : String(error);
                    const isDuplicateOutputError = /outputs have already been signed before/i.test(
                        errorMessage
                    );

                    if (wallet.bip39seed && blankOutputsCount > 0 && isDuplicateOutputError) {
                        wallet.warn(
                            `Wallet auto-repair: duplicate melt outputs detected for ${mint}. Retrying once with a new counter.`
                        );
                        await wallet.incrementDeterministicCounter(
                            counterEntry.counterKey,
                            blankOutputsCount
                        );
                        const retryCounter = (counter ?? 0) + blankOutputsCount;
                        meltResult = await cashuWallet.meltProofs(meltQuote, proofsToUse, {
                            counter: retryCounter,
                        });
                    } else {
                        throw error;
                    }
                }

                if (meltResult.quote.state === MeltQuoteState.PAID) {
                    return {
                        result: {
                            preimage: meltResult.quote.payment_preimage ?? "",
                        },
                        change: meltResult.change,
                    };
                }

                return null;
            }
        );

        return result;
    } catch (e) {
        if (e instanceof Error) {
            console.log("Failed to pay with mint %s: %s", mint, e.message);
            if (e.message.match(/already spent/i)) {
                console.log("Proofs already spent, consolidate mint tokens");
                setTimeout(() => {
                    consolidateMintTokens(mint, wallet);
                }, 2500);
            } else {
                throw e;
            }
        }

        return null;
    }
}
