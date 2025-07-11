import React, { useEffect, useState } from "react";
import { useWeb3React } from "@web3-react/core";
import cx from "classnames";
import useSWR from "swr";
import { ethers } from "ethers";

import Footer from "../Footer/Footer";
import Modal from "../Modal/Modal";

import "./Migration.css";

import { getConnectWalletHandler } from "lib/legacy";
import { getContract } from "config/contracts";

import Reader from "abis/Reader.json";
import Token from "abis/Token.json";
import UtxMigrator from "abis/UtxMigrator.json";
import { CHAIN_ID, getExplorerUrl } from "config/chains";
import { contractFetcher } from "lib/contracts";
import { helperToast } from "lib/helperToast";
import { useEagerConnect, useInactiveListener } from "lib/wallets";
import { approveTokens } from "domain/tokens";
import {
  bigNumberify,
  expandDecimals,
  formatAmount,
  formatAmountFree,
  formatArrayAmount,
  parseValue,
} from "lib/numbers";
import ExternalLink from "components/ExternalLink/ExternalLink";
import { t, Trans } from "@lingui/macro";

const { MaxUint256, AddressZero } = ethers.constants;

const precision = 1000000;
const decimals = 6;
const utxPrice = bigNumberify(2 * precision);
const tokens = [
  {
    name: "GMT",
    symbol: "GMT",
    address: getContract(CHAIN_ID, "GMT"),
    price: bigNumberify(10.97 * precision),
    iouToken: getContract(CHAIN_ID, "GMT_UTX_IOU"),
    cap: MaxUint256,
    bonus: 0,
  },
  {
    name: "xGMT",
    symbol: "xGMT",
    address: getContract(CHAIN_ID, "XGMT"),
    price: bigNumberify(90.31 * precision),
    iouToken: getContract(CHAIN_ID, "XGMT_UTX_IOU"),
    cap: MaxUint256,
    bonus: 0,
  },
  {
    name: "GMT-USDG",
    symbol: "LP",
    address: getContract(CHAIN_ID, "GMT_USDG_PAIR"),
    price: bigNumberify(parseInt(6.68 * precision)),
    iouToken: getContract(CHAIN_ID, "GMT_USDG_UTX_IOU"),
    cap: expandDecimals(483129, 18),
    bonus: 10,
  },
  {
    name: "xGMT-USDG",
    symbol: "LP",
    address: getContract(CHAIN_ID, "XGMT_USDG_PAIR"),
    price: bigNumberify(parseInt(19.27 * precision)),
    iouToken: getContract(CHAIN_ID, "XGMT_USDG_UTX_IOU"),
    cap: expandDecimals(150191, 18),
    bonus: 10,
  },
];

const readerAddress = getContract(CHAIN_ID, "Reader");
const utxMigratorAddress = getContract(CHAIN_ID, "UtxMigrator");

function MigrationModal(props) {
  const {
    isVisible,
    setIsVisible,
    isPendingApproval,
    setIsPendingApproval,
    value,
    setValue,
    index,
    balances,
    active,
    account,
    library,
  } = props;
  const token = tokens[index];
  const [isMigrating, setIsMigrating] = useState(false);
  const [isApproving, setIsApproving] = useState(false);

  const { data: tokenAllowance, mutate: updateTokenAllowance } = useSWR(
    [active, CHAIN_ID, token.address, "allowance", account, utxMigratorAddress],
    {
      fetcher: contractFetcher(library, Token),
    }
  );

  let maxAmount;
  if (balances) {
    maxAmount = balances[index * 2];
  }

  useEffect(() => {
    if (active) {
      library.on("block", () => {
        updateTokenAllowance(undefined, true);
      });
      return () => {
        library.removeAllListeners("block");
      };
    }
  }, [active, library, updateTokenAllowance]);

  let amount = parseValue(value, 18);
  const needApproval = tokenAllowance && amount && amount.gt(tokenAllowance);

  let baseAmount;
  let bonusAmount;
  let totalAmount;

  let baseAmountUsd;
  let bonusAmountUsd;
  let totalAmountUsd;

  if (amount) {
    baseAmount = amount.mul(token.price).div(utxPrice);
    bonusAmount = baseAmount.mul(token.bonus).div(100);
    totalAmount = baseAmount.add(bonusAmount);

    baseAmountUsd = baseAmount.mul(utxPrice);
    bonusAmountUsd = bonusAmount.mul(utxPrice);
    totalAmountUsd = totalAmount.mul(utxPrice);
  }

  const getError = () => {
    if (!amount || amount.eq(0)) {
      return t`Enter an amount`;
    }
    if (maxAmount && amount.gt(maxAmount)) {
      return t`Max amount exceeded`;
    }
  };

  const onClickPrimary = () => {
    if (needApproval) {
      approveTokens({
        setIsApproving,
        library,
        tokenAddress: token.address,
        spender: utxMigratorAddress,
        chainId: CHAIN_ID,
        onApproveSubmitted: () => {
          setIsPendingApproval(true);
        },
      });
      return;
    }

    setIsMigrating(true);
    const contract = new ethers.Contract(utxMigratorAddress, UtxMigrator.abi, library.getSigner());
    contract
      .migrate(token.address, amount)
      .then(async (res) => {
        const txUrl = getExplorerUrl(CHAIN_ID) + "tx/" + res.hash;
        helperToast.success(
          <div>
            <Trans>
              Migration submitted! <ExternalLink href={txUrl}>View status.</ExternalLink>
            </Trans>
          </div>
        );
        setIsVisible(false);
      })
      .catch((e) => {
        // eslint-disable-next-line no-console
        console.error(e);
        helperToast.error(t`Migration failed`);
      })
      .finally(() => {
        setIsMigrating(false);
      });
  };

  const isPrimaryEnabled = () => {
    const error = getError();
    if (error) {
      return false;
    }
    if (isApproving) {
      return false;
    }
    if (isMigrating) {
      return false;
    }
    if (needApproval && isPendingApproval) {
      return false;
    }
    return true;
  };

  const getPrimaryText = () => {
    const error = getError();
    if (error) {
      return error;
    }
    if (isApproving) {
      return t`Approving...`;
    }
    if (needApproval && isPendingApproval) {
      return t`Waiting for Approval`;
    }
    if (needApproval) {
      return t`Approve ${token.name}`;
    }
    if (isMigrating) {
      return t`Migrating...`;
    }
    return t`Migrate`;
  };

  return (
    <div className="StakeModal">
      <Modal isVisible={isVisible} setIsVisible={setIsVisible} label={`Migrate ${token.name}`}>
        <div className="Exchange-swap-section">
          <div className="Exchange-swap-section-top">
            <div className="muted">
              <div className="Exchange-swap-usd">Migrate</div>
            </div>
            <div className="muted align-right clickable" onClick={() => setValue(formatAmountFree(maxAmount, 18, 8))}>
              <Trans>Max: {formatAmount(maxAmount, 18, 4, true)}</Trans>
            </div>
          </div>
          <div className="Exchange-swap-section-bottom">
            <div>
              <input
                type="number"
                placeholder="0.0"
                className="Exchange-swap-input"
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </div>
            <div className="PositionEditor-token-symbol">{token.symbol}</div>
          </div>
        </div>
        <div className="MigrationModal-info-box">
          <div className="App-info-row">
            <div className="App-info-label">{token.bonus > 0 ? "Base Tokens" : "To Receive"}</div>
            <div className="align-right">
              {baseAmount &&
                `${formatAmount(baseAmount, 18, 4, true)} UTX ($${formatAmount(
                  baseAmountUsd,
                  18 + decimals,
                  2,
                  true
                )})`}
              {!baseAmount && "-"}
            </div>
          </div>
          {token.bonus > 0 && (
            <div className="App-info-row">
              <div className="App-info-label">
                <Trans>Bonus Tokens</Trans>
              </div>
              <div className="align-right">
                {bonusAmount &&
                  `${formatAmount(bonusAmount, 18, 4, true)} UTX ($${formatAmount(
                    bonusAmountUsd,
                    18 + decimals,
                    2,
                    true
                  )})`}
                {!bonusAmount && "-"}
              </div>
            </div>
          )}
          {token.bonus > 0 && (
            <div className="App-info-row">
              <div className="App-info-label">
                <Trans>To Receive</Trans>
              </div>
              <div className="align-right">
                {totalAmount &&
                  `${formatAmount(totalAmount, 18, 4, true)} UTX ($${formatAmount(
                    totalAmountUsd,
                    18 + decimals,
                    2,
                    true
                  )})`}
                {!totalAmount && "-"}
              </div>
            </div>
          )}
        </div>
        <div className="Exchange-swap-button-container">
          <button className="App-cta Exchange-swap-button" onClick={onClickPrimary} disabled={!isPrimaryEnabled()}>
            {getPrimaryText()}
          </button>
        </div>
      </Modal>
    </div>
  );
}

export default function Migration() {
  const [isMigrationModalVisible, setIsMigrationModalVisible] = useState(false);
  const [isPendingApproval, setIsPendingApproval] = useState(false);
  const [migrationIndex, setMigrationIndex] = useState(0);
  const [migrationValue, setMigrationValue] = useState("");

  const { connector, activate, active, account, library } = useWeb3React();
  const [activatingConnector, setActivatingConnector] = useState();
  useEffect(() => {
    if (activatingConnector && activatingConnector === connector) {
      setActivatingConnector(undefined);
    }
  }, [activatingConnector, connector]);
  const triedEager = useEagerConnect();
  useInactiveListener(!triedEager || !!activatingConnector);
  const connectWallet = getConnectWalletHandler(activate);

  const tokenAddresses = tokens.map((token) => token.address);
  const iouTokenAddresses = tokens.map((token) => token.iouToken);

  const { data: iouBalances, mutate: updateIouBalances } = useSWR(
    ["Migration:iouBalances", CHAIN_ID, readerAddress, "getTokenBalancesWithSupplies", account || AddressZero],
    {
      fetcher: contractFetcher(library, Reader, [iouTokenAddresses]),
    }
  );

  const { data: balances, mutate: updateBalances } = useSWR(
    ["Migration:balances", CHAIN_ID, readerAddress, "getTokenBalancesWithSupplies", account || AddressZero],
    {
      fetcher: contractFetcher(library, Reader, [tokenAddresses]),
    }
  );

  const { data: migratedAmounts, mutate: updateMigratedAmounts } = useSWR(
    ["Migration:migratedAmounts", CHAIN_ID, utxMigratorAddress, "getTokenAmounts"],
    {
      fetcher: contractFetcher(library, UtxMigrator, [tokenAddresses]),
    }
  );

  let utxBalance;
  let totalMigratedUtx;
  let totalMigratedUsd;

  if (iouBalances) {
    utxBalance = bigNumberify(0);
    totalMigratedUtx = bigNumberify(0);

    for (let i = 0; i < iouBalances.length / 2; i++) {
      utxBalance = utxBalance.add(iouBalances[i * 2]);
      totalMigratedUtx = totalMigratedUtx.add(iouBalances[i * 2 + 1]);
    }

    totalMigratedUsd = totalMigratedUtx.mul(utxPrice);
  }

  useEffect(() => {
    if (active) {
      library.on("block", () => {
        updateBalances(undefined, true);
        updateIouBalances(undefined, true);
        updateMigratedAmounts(undefined, true);
      });
      return () => {
        library.removeAllListeners("block");
      };
    }
  }, [active, library, updateBalances, updateIouBalances, updateMigratedAmounts]);

  const showMigrationModal = (index) => {
    setIsPendingApproval(false);
    setMigrationValue("");
    setMigrationIndex(index);
    setIsMigrationModalVisible(true);
  };

  return (
    <div className="Migration Page">
      <MigrationModal
        isVisible={isMigrationModalVisible}
        setIsVisible={setIsMigrationModalVisible}
        isPendingApproval={isPendingApproval}
        setIsPendingApproval={setIsPendingApproval}
        value={migrationValue}
        setValue={setMigrationValue}
        index={migrationIndex}
        balances={balances}
        active={active}
        account={account}
        library={library}
      />
      <div>
        <div className="Stake-title App-hero">
          <div className="Stake-title-primary App-hero-primary">
            ${formatAmount(totalMigratedUsd, decimals + 18, 0, true)}
          </div>
          <div className="Stake-title-secondary">
            <Trans>Total Assets Migrated</Trans>
          </div>
        </div>
      </div>
      <div className="Migration-note">
        <Trans>Your wallet: {formatAmount(utxBalance, 18, 4, true)}</Trans> UTX
      </div>
      <div className="Migration-cards">
        {tokens.map((token, index) => {
          const { cap, price, bonus } = token;
          const hasCap = cap.lt(MaxUint256);
          return (
            <div className={cx("border", "App-card", { primary: index === 0 })} key={index}>
              <div className="Stake-card-title App-card-title">{token.name}</div>
              <div className="Stake-card-bottom App-card-content">
                <div className="Stake-info App-card-row">
                  <div className="label">
                    <Trans>Wallet</Trans>
                  </div>
                  <div>{formatArrayAmount(balances, index * 2, 18, 4, true)}</div>
                </div>
                <div className="Stake-info App-card-row">
                  <div className="label">
                    <Trans>Migration Price</Trans>
                  </div>
                  <div>${formatAmount(price, decimals, 2, true)}</div>
                </div>
                <div className="Stake-info App-card-row">
                  <div className="label">
                    <Trans>Bonus Tokens</Trans>
                  </div>
                  <div>{parseFloat(bonus).toFixed(2)}%</div>
                </div>
                <div className="Stake-info App-card-row">
                  <div className="label">
                    <Trans>Migrated</Trans>
                  </div>
                  {!hasCap && <div>{formatArrayAmount(migratedAmounts, index, 18, 0, true)}</div>}
                  {hasCap && (
                    <div>
                      {formatArrayAmount(migratedAmounts, index, 18, 0, true)} / {formatAmount(cap, 18, 0, true)}
                    </div>
                  )}
                </div>
                <div className="App-card-options">
                  {!active && (
                    <button className="App-button-option App-card-option" onClick={connectWallet}>
                      <Trans>Connect Wallet</Trans>
                    </button>
                  )}
                  {active && (
                    <button className="App-button-option App-card-option" onClick={() => showMigrationModal(index)}>
                      <Trans>Migrate</Trans>
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <Footer />
    </div>
  );
}
