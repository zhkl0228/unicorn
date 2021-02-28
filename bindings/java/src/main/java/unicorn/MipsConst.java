// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

package unicorn;

public interface MipsConst {

// MIPS registers

   int UC_MIPS_REG_INVALID = 0;

// General purpose registers
   int UC_MIPS_REG_PC = 1;
   int UC_MIPS_REG_0 = 2;
   int UC_MIPS_REG_1 = 3;
   int UC_MIPS_REG_2 = 4;
   int UC_MIPS_REG_3 = 5;
   int UC_MIPS_REG_4 = 6;
   int UC_MIPS_REG_5 = 7;
   int UC_MIPS_REG_6 = 8;
   int UC_MIPS_REG_7 = 9;
   int UC_MIPS_REG_8 = 10;
   int UC_MIPS_REG_9 = 11;
   int UC_MIPS_REG_10 = 12;
   int UC_MIPS_REG_11 = 13;
   int UC_MIPS_REG_12 = 14;
   int UC_MIPS_REG_13 = 15;
   int UC_MIPS_REG_14 = 16;
   int UC_MIPS_REG_15 = 17;
   int UC_MIPS_REG_16 = 18;
   int UC_MIPS_REG_17 = 19;
   int UC_MIPS_REG_18 = 20;
   int UC_MIPS_REG_19 = 21;
   int UC_MIPS_REG_20 = 22;
   int UC_MIPS_REG_21 = 23;
   int UC_MIPS_REG_22 = 24;
   int UC_MIPS_REG_23 = 25;
   int UC_MIPS_REG_24 = 26;
   int UC_MIPS_REG_25 = 27;
   int UC_MIPS_REG_26 = 28;
   int UC_MIPS_REG_27 = 29;
   int UC_MIPS_REG_28 = 30;
   int UC_MIPS_REG_29 = 31;
   int UC_MIPS_REG_30 = 32;
   int UC_MIPS_REG_31 = 33;

// DSP registers
   int UC_MIPS_REG_DSPCCOND = 34;
   int UC_MIPS_REG_DSPCARRY = 35;
   int UC_MIPS_REG_DSPEFI = 36;
   int UC_MIPS_REG_DSPOUTFLAG = 37;
   int UC_MIPS_REG_DSPOUTFLAG16_19 = 38;
   int UC_MIPS_REG_DSPOUTFLAG20 = 39;
   int UC_MIPS_REG_DSPOUTFLAG21 = 40;
   int UC_MIPS_REG_DSPOUTFLAG22 = 41;
   int UC_MIPS_REG_DSPOUTFLAG23 = 42;
   int UC_MIPS_REG_DSPPOS = 43;
   int UC_MIPS_REG_DSPSCOUNT = 44;

// ACC registers
   int UC_MIPS_REG_AC0 = 45;
   int UC_MIPS_REG_AC1 = 46;
   int UC_MIPS_REG_AC2 = 47;
   int UC_MIPS_REG_AC3 = 48;

// COP registers
   int UC_MIPS_REG_CC0 = 49;
   int UC_MIPS_REG_CC1 = 50;
   int UC_MIPS_REG_CC2 = 51;
   int UC_MIPS_REG_CC3 = 52;
   int UC_MIPS_REG_CC4 = 53;
   int UC_MIPS_REG_CC5 = 54;
   int UC_MIPS_REG_CC6 = 55;
   int UC_MIPS_REG_CC7 = 56;

// FPU registers
   int UC_MIPS_REG_F0 = 57;
   int UC_MIPS_REG_F1 = 58;
   int UC_MIPS_REG_F2 = 59;
   int UC_MIPS_REG_F3 = 60;
   int UC_MIPS_REG_F4 = 61;
   int UC_MIPS_REG_F5 = 62;
   int UC_MIPS_REG_F6 = 63;
   int UC_MIPS_REG_F7 = 64;
   int UC_MIPS_REG_F8 = 65;
   int UC_MIPS_REG_F9 = 66;
   int UC_MIPS_REG_F10 = 67;
   int UC_MIPS_REG_F11 = 68;
   int UC_MIPS_REG_F12 = 69;
   int UC_MIPS_REG_F13 = 70;
   int UC_MIPS_REG_F14 = 71;
   int UC_MIPS_REG_F15 = 72;
   int UC_MIPS_REG_F16 = 73;
   int UC_MIPS_REG_F17 = 74;
   int UC_MIPS_REG_F18 = 75;
   int UC_MIPS_REG_F19 = 76;
   int UC_MIPS_REG_F20 = 77;
   int UC_MIPS_REG_F21 = 78;
   int UC_MIPS_REG_F22 = 79;
   int UC_MIPS_REG_F23 = 80;
   int UC_MIPS_REG_F24 = 81;
   int UC_MIPS_REG_F25 = 82;
   int UC_MIPS_REG_F26 = 83;
   int UC_MIPS_REG_F27 = 84;
   int UC_MIPS_REG_F28 = 85;
   int UC_MIPS_REG_F29 = 86;
   int UC_MIPS_REG_F30 = 87;
   int UC_MIPS_REG_F31 = 88;
   int UC_MIPS_REG_FCC0 = 89;
   int UC_MIPS_REG_FCC1 = 90;
   int UC_MIPS_REG_FCC2 = 91;
   int UC_MIPS_REG_FCC3 = 92;
   int UC_MIPS_REG_FCC4 = 93;
   int UC_MIPS_REG_FCC5 = 94;
   int UC_MIPS_REG_FCC6 = 95;
   int UC_MIPS_REG_FCC7 = 96;

// AFPR128
   int UC_MIPS_REG_W0 = 97;
   int UC_MIPS_REG_W1 = 98;
   int UC_MIPS_REG_W2 = 99;
   int UC_MIPS_REG_W3 = 100;
   int UC_MIPS_REG_W4 = 101;
   int UC_MIPS_REG_W5 = 102;
   int UC_MIPS_REG_W6 = 103;
   int UC_MIPS_REG_W7 = 104;
   int UC_MIPS_REG_W8 = 105;
   int UC_MIPS_REG_W9 = 106;
   int UC_MIPS_REG_W10 = 107;
   int UC_MIPS_REG_W11 = 108;
   int UC_MIPS_REG_W12 = 109;
   int UC_MIPS_REG_W13 = 110;
   int UC_MIPS_REG_W14 = 111;
   int UC_MIPS_REG_W15 = 112;
   int UC_MIPS_REG_W16 = 113;
   int UC_MIPS_REG_W17 = 114;
   int UC_MIPS_REG_W18 = 115;
   int UC_MIPS_REG_W19 = 116;
   int UC_MIPS_REG_W20 = 117;
   int UC_MIPS_REG_W21 = 118;
   int UC_MIPS_REG_W22 = 119;
   int UC_MIPS_REG_W23 = 120;
   int UC_MIPS_REG_W24 = 121;
   int UC_MIPS_REG_W25 = 122;
   int UC_MIPS_REG_W26 = 123;
   int UC_MIPS_REG_W27 = 124;
   int UC_MIPS_REG_W28 = 125;
   int UC_MIPS_REG_W29 = 126;
   int UC_MIPS_REG_W30 = 127;
   int UC_MIPS_REG_W31 = 128;
   int UC_MIPS_REG_HI = 129;
   int UC_MIPS_REG_LO = 130;
   int UC_MIPS_REG_P0 = 131;
   int UC_MIPS_REG_P1 = 132;
   int UC_MIPS_REG_P2 = 133;
   int UC_MIPS_REG_MPL0 = 134;
   int UC_MIPS_REG_MPL1 = 135;
   int UC_MIPS_REG_MPL2 = 136;
   int UC_MIPS_REG_CP0_CONFIG3 = 137;
   int UC_MIPS_REG_CP0_USERLOCAL = 138;
   int UC_MIPS_REG_ENDING = 139;
   int UC_MIPS_REG_ZERO = 2;
   int UC_MIPS_REG_AT = 3;
   int UC_MIPS_REG_V0 = 4;
   int UC_MIPS_REG_V1 = 5;
   int UC_MIPS_REG_A0 = 6;
   int UC_MIPS_REG_A1 = 7;
   int UC_MIPS_REG_A2 = 8;
   int UC_MIPS_REG_A3 = 9;
   int UC_MIPS_REG_T0 = 10;
   int UC_MIPS_REG_T1 = 11;
   int UC_MIPS_REG_T2 = 12;
   int UC_MIPS_REG_T3 = 13;
   int UC_MIPS_REG_T4 = 14;
   int UC_MIPS_REG_T5 = 15;
   int UC_MIPS_REG_T6 = 16;
   int UC_MIPS_REG_T7 = 17;
   int UC_MIPS_REG_S0 = 18;
   int UC_MIPS_REG_S1 = 19;
   int UC_MIPS_REG_S2 = 20;
   int UC_MIPS_REG_S3 = 21;
   int UC_MIPS_REG_S4 = 22;
   int UC_MIPS_REG_S5 = 23;
   int UC_MIPS_REG_S6 = 24;
   int UC_MIPS_REG_S7 = 25;
   int UC_MIPS_REG_T8 = 26;
   int UC_MIPS_REG_T9 = 27;
   int UC_MIPS_REG_K0 = 28;
   int UC_MIPS_REG_K1 = 29;
   int UC_MIPS_REG_GP = 30;
   int UC_MIPS_REG_SP = 31;
   int UC_MIPS_REG_FP = 32;
   int UC_MIPS_REG_S8 = 32;
   int UC_MIPS_REG_RA = 33;
   int UC_MIPS_REG_HI0 = 45;
   int UC_MIPS_REG_HI1 = 46;
   int UC_MIPS_REG_HI2 = 47;
   int UC_MIPS_REG_HI3 = 48;
   int UC_MIPS_REG_LO0 = 45;
   int UC_MIPS_REG_LO1 = 46;
   int UC_MIPS_REG_LO2 = 47;
   int UC_MIPS_REG_LO3 = 48;

}
