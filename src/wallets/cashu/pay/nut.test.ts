import { findMintsInCommon, createToken } from "./nut";
import type { NDKCashuWallet } from "../wallet";
import type { MintUrl } from "../mint/utils";
import { withProofReserve } from "../wallet/effect";
import { consolidateMintTokens } from "../validate.js";

jest.mock("../wallet/effect", () => ({
    withProofReserve: jest.fn(),
}));
jest.mock("../validate.js", () => ({
    consolidateMintTokens: jest.fn(),
}));

const withProofReserveMock = jest.mocked(withProofReserve);
const consolidateMintTokensMock = jest.mocked(consolidateMintTokens);

describe("nut.ts", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe("findMintsInCommon", () => {
        it("should return mints that are common in all collections", () => {
            const user1Mints: MintUrl[] = ["https://mint1.com", "https://mint2.com"];
            const user2Mints: MintUrl[] = ["https://mint2.com", "https://mint3.com"];
            const user3Mints: MintUrl[] = ["https://mint1.com", "https://mint2.com"];

            const result = findMintsInCommon([user1Mints, user2Mints, user3Mints]);
            expect(result).toEqual(["https://mint2.com"]);
        });

        it("should return an empty array if no mints are common", () => {
            const user1Mints: MintUrl[] = ["https://mint1.com"];
            const user2Mints: MintUrl[] = ["https://mint2.com"];

            const result = findMintsInCommon([user1Mints, user2Mints]);
            expect(result).toEqual([]);
        });
    });

    describe("createToken", () => {
        it("retries after consolidating already spent proofs", async () => {
            const wallet = {
                getMintsWithBalance: jest.fn().mockReturnValue(["https://mint.test"]),
                getCashuWallet: jest
                    .fn()
                    .mockResolvedValue({ mint: { mintUrl: "https://mint.test" } }),
                state: {
                    getCounterEntryFor: jest
                        .fn()
                        .mockResolvedValue({ counterKey: "mint|keyset", counter: 0 })
                },
                bip39seed: undefined,
            } as unknown as NDKCashuWallet;

            withProofReserveMock
                .mockRejectedValueOnce(new Error("Token already spent."))
                .mockResolvedValueOnce({
                    result: {
                        proofs: [{ amount: 1, C: "c1" }],
                        mint: "https://mint.test",
                    },
                    proofsChange: {
                        mint: "https://mint.test",
                        store: [],
                        destroy: [],
                    },
                    stateUpdate: null,
                    mint: "https://mint.test",
                    fee: 0,
                } as any);

            consolidateMintTokensMock.mockResolvedValue(undefined as any);

            const result = await createToken(wallet, 1, ["https://mint.test"]);

            expect(result?.result?.mint).toBe("https://mint.test");
            expect(withProofReserveMock).toHaveBeenCalledTimes(2);
            expect(consolidateMintTokensMock).toHaveBeenCalledWith("https://mint.test", wallet);
        });
    });

    // Remove tests for createTokenForPayment since it doesn't exist
});
