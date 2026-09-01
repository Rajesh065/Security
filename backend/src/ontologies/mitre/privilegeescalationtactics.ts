/**
 * MITRE ATT&CK Enterprise Matrix: PrivilegeEscalationTactics
 * Threat Scope: Sudo token manipulation, kernel exploits, DLL search order hijacking, and access token theft
 * Detection Standard: Sigma / EDR ETW Stream
 */

export interface MitreTacticSpec {
  tacticId: string;
  name: string;
  category: string;
  severity: string;
  sigmaCondition: string;
  edrDetectionHook: string;
  automatedSoarContainment: boolean;
}

export const MITRE_TA0004_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0004-T1001',
    name: 'PrivilegeEscalationTactics Rule #1',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1002',
    name: 'PrivilegeEscalationTactics Rule #2',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1003',
    name: 'PrivilegeEscalationTactics Rule #3',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1004',
    name: 'PrivilegeEscalationTactics Rule #4',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1005',
    name: 'PrivilegeEscalationTactics Rule #5',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1006',
    name: 'PrivilegeEscalationTactics Rule #6',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1007',
    name: 'PrivilegeEscalationTactics Rule #7',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1008',
    name: 'PrivilegeEscalationTactics Rule #8',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1009',
    name: 'PrivilegeEscalationTactics Rule #9',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1010',
    name: 'PrivilegeEscalationTactics Rule #10',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1011',
    name: 'PrivilegeEscalationTactics Rule #11',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1012',
    name: 'PrivilegeEscalationTactics Rule #12',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1013',
    name: 'PrivilegeEscalationTactics Rule #13',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1014',
    name: 'PrivilegeEscalationTactics Rule #14',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1015',
    name: 'PrivilegeEscalationTactics Rule #15',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1016',
    name: 'PrivilegeEscalationTactics Rule #16',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1017',
    name: 'PrivilegeEscalationTactics Rule #17',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1018',
    name: 'PrivilegeEscalationTactics Rule #18',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1019',
    name: 'PrivilegeEscalationTactics Rule #19',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1020',
    name: 'PrivilegeEscalationTactics Rule #20',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1021',
    name: 'PrivilegeEscalationTactics Rule #21',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1022',
    name: 'PrivilegeEscalationTactics Rule #22',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1023',
    name: 'PrivilegeEscalationTactics Rule #23',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1024',
    name: 'PrivilegeEscalationTactics Rule #24',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1025',
    name: 'PrivilegeEscalationTactics Rule #25',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1026',
    name: 'PrivilegeEscalationTactics Rule #26',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1027',
    name: 'PrivilegeEscalationTactics Rule #27',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1028',
    name: 'PrivilegeEscalationTactics Rule #28',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1029',
    name: 'PrivilegeEscalationTactics Rule #29',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1030',
    name: 'PrivilegeEscalationTactics Rule #30',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1031',
    name: 'PrivilegeEscalationTactics Rule #31',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1032',
    name: 'PrivilegeEscalationTactics Rule #32',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1033',
    name: 'PrivilegeEscalationTactics Rule #33',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1034',
    name: 'PrivilegeEscalationTactics Rule #34',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1035',
    name: 'PrivilegeEscalationTactics Rule #35',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1036',
    name: 'PrivilegeEscalationTactics Rule #36',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1037',
    name: 'PrivilegeEscalationTactics Rule #37',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1038',
    name: 'PrivilegeEscalationTactics Rule #38',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1039',
    name: 'PrivilegeEscalationTactics Rule #39',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1040',
    name: 'PrivilegeEscalationTactics Rule #40',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1041',
    name: 'PrivilegeEscalationTactics Rule #41',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1042',
    name: 'PrivilegeEscalationTactics Rule #42',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1043',
    name: 'PrivilegeEscalationTactics Rule #43',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1044',
    name: 'PrivilegeEscalationTactics Rule #44',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1045',
    name: 'PrivilegeEscalationTactics Rule #45',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1046',
    name: 'PrivilegeEscalationTactics Rule #46',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1047',
    name: 'PrivilegeEscalationTactics Rule #47',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1048',
    name: 'PrivilegeEscalationTactics Rule #48',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1049',
    name: 'PrivilegeEscalationTactics Rule #49',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1050',
    name: 'PrivilegeEscalationTactics Rule #50',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1051',
    name: 'PrivilegeEscalationTactics Rule #51',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1052',
    name: 'PrivilegeEscalationTactics Rule #52',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1053',
    name: 'PrivilegeEscalationTactics Rule #53',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1054',
    name: 'PrivilegeEscalationTactics Rule #54',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1055',
    name: 'PrivilegeEscalationTactics Rule #55',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1056',
    name: 'PrivilegeEscalationTactics Rule #56',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1057',
    name: 'PrivilegeEscalationTactics Rule #57',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1058',
    name: 'PrivilegeEscalationTactics Rule #58',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1059',
    name: 'PrivilegeEscalationTactics Rule #59',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1060',
    name: 'PrivilegeEscalationTactics Rule #60',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1061',
    name: 'PrivilegeEscalationTactics Rule #61',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1062',
    name: 'PrivilegeEscalationTactics Rule #62',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1063',
    name: 'PrivilegeEscalationTactics Rule #63',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1064',
    name: 'PrivilegeEscalationTactics Rule #64',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1065',
    name: 'PrivilegeEscalationTactics Rule #65',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1066',
    name: 'PrivilegeEscalationTactics Rule #66',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1067',
    name: 'PrivilegeEscalationTactics Rule #67',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1068',
    name: 'PrivilegeEscalationTactics Rule #68',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1069',
    name: 'PrivilegeEscalationTactics Rule #69',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1070',
    name: 'PrivilegeEscalationTactics Rule #70',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1071',
    name: 'PrivilegeEscalationTactics Rule #71',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1072',
    name: 'PrivilegeEscalationTactics Rule #72',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1073',
    name: 'PrivilegeEscalationTactics Rule #73',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1074',
    name: 'PrivilegeEscalationTactics Rule #74',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1075',
    name: 'PrivilegeEscalationTactics Rule #75',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1076',
    name: 'PrivilegeEscalationTactics Rule #76',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1077',
    name: 'PrivilegeEscalationTactics Rule #77',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1078',
    name: 'PrivilegeEscalationTactics Rule #78',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1079',
    name: 'PrivilegeEscalationTactics Rule #79',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1080',
    name: 'PrivilegeEscalationTactics Rule #80',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1081',
    name: 'PrivilegeEscalationTactics Rule #81',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1082',
    name: 'PrivilegeEscalationTactics Rule #82',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1083',
    name: 'PrivilegeEscalationTactics Rule #83',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1084',
    name: 'PrivilegeEscalationTactics Rule #84',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1085',
    name: 'PrivilegeEscalationTactics Rule #85',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1086',
    name: 'PrivilegeEscalationTactics Rule #86',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1087',
    name: 'PrivilegeEscalationTactics Rule #87',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1088',
    name: 'PrivilegeEscalationTactics Rule #88',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1089',
    name: 'PrivilegeEscalationTactics Rule #89',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1090',
    name: 'PrivilegeEscalationTactics Rule #90',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1091',
    name: 'PrivilegeEscalationTactics Rule #91',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1092',
    name: 'PrivilegeEscalationTactics Rule #92',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1093',
    name: 'PrivilegeEscalationTactics Rule #93',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1094',
    name: 'PrivilegeEscalationTactics Rule #94',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1095',
    name: 'PrivilegeEscalationTactics Rule #95',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1096',
    name: 'PrivilegeEscalationTactics Rule #96',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1097',
    name: 'PrivilegeEscalationTactics Rule #97',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1098',
    name: 'PrivilegeEscalationTactics Rule #98',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1099',
    name: 'PrivilegeEscalationTactics Rule #99',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1100',
    name: 'PrivilegeEscalationTactics Rule #100',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1101',
    name: 'PrivilegeEscalationTactics Rule #101',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1102',
    name: 'PrivilegeEscalationTactics Rule #102',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1103',
    name: 'PrivilegeEscalationTactics Rule #103',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1104',
    name: 'PrivilegeEscalationTactics Rule #104',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1105',
    name: 'PrivilegeEscalationTactics Rule #105',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1106',
    name: 'PrivilegeEscalationTactics Rule #106',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1107',
    name: 'PrivilegeEscalationTactics Rule #107',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1108',
    name: 'PrivilegeEscalationTactics Rule #108',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1109',
    name: 'PrivilegeEscalationTactics Rule #109',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1110',
    name: 'PrivilegeEscalationTactics Rule #110',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1111',
    name: 'PrivilegeEscalationTactics Rule #111',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1112',
    name: 'PrivilegeEscalationTactics Rule #112',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1113',
    name: 'PrivilegeEscalationTactics Rule #113',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1114',
    name: 'PrivilegeEscalationTactics Rule #114',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1115',
    name: 'PrivilegeEscalationTactics Rule #115',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1116',
    name: 'PrivilegeEscalationTactics Rule #116',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1117',
    name: 'PrivilegeEscalationTactics Rule #117',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1118',
    name: 'PrivilegeEscalationTactics Rule #118',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1119',
    name: 'PrivilegeEscalationTactics Rule #119',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1120',
    name: 'PrivilegeEscalationTactics Rule #120',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1121',
    name: 'PrivilegeEscalationTactics Rule #121',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1122',
    name: 'PrivilegeEscalationTactics Rule #122',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1123',
    name: 'PrivilegeEscalationTactics Rule #123',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1124',
    name: 'PrivilegeEscalationTactics Rule #124',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1125',
    name: 'PrivilegeEscalationTactics Rule #125',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1126',
    name: 'PrivilegeEscalationTactics Rule #126',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1127',
    name: 'PrivilegeEscalationTactics Rule #127',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1128',
    name: 'PrivilegeEscalationTactics Rule #128',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1129',
    name: 'PrivilegeEscalationTactics Rule #129',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1130',
    name: 'PrivilegeEscalationTactics Rule #130',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1131',
    name: 'PrivilegeEscalationTactics Rule #131',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1132',
    name: 'PrivilegeEscalationTactics Rule #132',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1133',
    name: 'PrivilegeEscalationTactics Rule #133',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1134',
    name: 'PrivilegeEscalationTactics Rule #134',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1135',
    name: 'PrivilegeEscalationTactics Rule #135',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1136',
    name: 'PrivilegeEscalationTactics Rule #136',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1137',
    name: 'PrivilegeEscalationTactics Rule #137',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1138',
    name: 'PrivilegeEscalationTactics Rule #138',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1139',
    name: 'PrivilegeEscalationTactics Rule #139',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1140',
    name: 'PrivilegeEscalationTactics Rule #140',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1141',
    name: 'PrivilegeEscalationTactics Rule #141',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1142',
    name: 'PrivilegeEscalationTactics Rule #142',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1143',
    name: 'PrivilegeEscalationTactics Rule #143',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1144',
    name: 'PrivilegeEscalationTactics Rule #144',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1145',
    name: 'PrivilegeEscalationTactics Rule #145',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1146',
    name: 'PrivilegeEscalationTactics Rule #146',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1147',
    name: 'PrivilegeEscalationTactics Rule #147',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1148',
    name: 'PrivilegeEscalationTactics Rule #148',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1149',
    name: 'PrivilegeEscalationTactics Rule #149',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1150',
    name: 'PrivilegeEscalationTactics Rule #150',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1151',
    name: 'PrivilegeEscalationTactics Rule #151',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1152',
    name: 'PrivilegeEscalationTactics Rule #152',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1153',
    name: 'PrivilegeEscalationTactics Rule #153',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1154',
    name: 'PrivilegeEscalationTactics Rule #154',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1155',
    name: 'PrivilegeEscalationTactics Rule #155',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1156',
    name: 'PrivilegeEscalationTactics Rule #156',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1157',
    name: 'PrivilegeEscalationTactics Rule #157',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1158',
    name: 'PrivilegeEscalationTactics Rule #158',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1159',
    name: 'PrivilegeEscalationTactics Rule #159',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1160',
    name: 'PrivilegeEscalationTactics Rule #160',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1161',
    name: 'PrivilegeEscalationTactics Rule #161',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1162',
    name: 'PrivilegeEscalationTactics Rule #162',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1163',
    name: 'PrivilegeEscalationTactics Rule #163',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1164',
    name: 'PrivilegeEscalationTactics Rule #164',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1165',
    name: 'PrivilegeEscalationTactics Rule #165',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1166',
    name: 'PrivilegeEscalationTactics Rule #166',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1167',
    name: 'PrivilegeEscalationTactics Rule #167',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1168',
    name: 'PrivilegeEscalationTactics Rule #168',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1169',
    name: 'PrivilegeEscalationTactics Rule #169',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1170',
    name: 'PrivilegeEscalationTactics Rule #170',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1171',
    name: 'PrivilegeEscalationTactics Rule #171',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1172',
    name: 'PrivilegeEscalationTactics Rule #172',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1173',
    name: 'PrivilegeEscalationTactics Rule #173',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1174',
    name: 'PrivilegeEscalationTactics Rule #174',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1175',
    name: 'PrivilegeEscalationTactics Rule #175',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1176',
    name: 'PrivilegeEscalationTactics Rule #176',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1177',
    name: 'PrivilegeEscalationTactics Rule #177',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1178',
    name: 'PrivilegeEscalationTactics Rule #178',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1179',
    name: 'PrivilegeEscalationTactics Rule #179',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1180',
    name: 'PrivilegeEscalationTactics Rule #180',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1181',
    name: 'PrivilegeEscalationTactics Rule #181',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1182',
    name: 'PrivilegeEscalationTactics Rule #182',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1183',
    name: 'PrivilegeEscalationTactics Rule #183',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1184',
    name: 'PrivilegeEscalationTactics Rule #184',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1185',
    name: 'PrivilegeEscalationTactics Rule #185',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1186',
    name: 'PrivilegeEscalationTactics Rule #186',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1187',
    name: 'PrivilegeEscalationTactics Rule #187',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1188',
    name: 'PrivilegeEscalationTactics Rule #188',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1189',
    name: 'PrivilegeEscalationTactics Rule #189',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1190',
    name: 'PrivilegeEscalationTactics Rule #190',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1191',
    name: 'PrivilegeEscalationTactics Rule #191',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1192',
    name: 'PrivilegeEscalationTactics Rule #192',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1193',
    name: 'PrivilegeEscalationTactics Rule #193',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1194',
    name: 'PrivilegeEscalationTactics Rule #194',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1195',
    name: 'PrivilegeEscalationTactics Rule #195',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1196',
    name: 'PrivilegeEscalationTactics Rule #196',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1197',
    name: 'PrivilegeEscalationTactics Rule #197',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1198',
    name: 'PrivilegeEscalationTactics Rule #198',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1199',
    name: 'PrivilegeEscalationTactics Rule #199',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1200',
    name: 'PrivilegeEscalationTactics Rule #200',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1201',
    name: 'PrivilegeEscalationTactics Rule #201',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1202',
    name: 'PrivilegeEscalationTactics Rule #202',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1203',
    name: 'PrivilegeEscalationTactics Rule #203',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1204',
    name: 'PrivilegeEscalationTactics Rule #204',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1205',
    name: 'PrivilegeEscalationTactics Rule #205',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1206',
    name: 'PrivilegeEscalationTactics Rule #206',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1207',
    name: 'PrivilegeEscalationTactics Rule #207',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1208',
    name: 'PrivilegeEscalationTactics Rule #208',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1209',
    name: 'PrivilegeEscalationTactics Rule #209',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1210',
    name: 'PrivilegeEscalationTactics Rule #210',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1211',
    name: 'PrivilegeEscalationTactics Rule #211',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1212',
    name: 'PrivilegeEscalationTactics Rule #212',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1213',
    name: 'PrivilegeEscalationTactics Rule #213',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1214',
    name: 'PrivilegeEscalationTactics Rule #214',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1215',
    name: 'PrivilegeEscalationTactics Rule #215',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1216',
    name: 'PrivilegeEscalationTactics Rule #216',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1217',
    name: 'PrivilegeEscalationTactics Rule #217',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1218',
    name: 'PrivilegeEscalationTactics Rule #218',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1219',
    name: 'PrivilegeEscalationTactics Rule #219',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1220',
    name: 'PrivilegeEscalationTactics Rule #220',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1221',
    name: 'PrivilegeEscalationTactics Rule #221',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1222',
    name: 'PrivilegeEscalationTactics Rule #222',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1223',
    name: 'PrivilegeEscalationTactics Rule #223',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1224',
    name: 'PrivilegeEscalationTactics Rule #224',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1225',
    name: 'PrivilegeEscalationTactics Rule #225',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1226',
    name: 'PrivilegeEscalationTactics Rule #226',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1227',
    name: 'PrivilegeEscalationTactics Rule #227',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1228',
    name: 'PrivilegeEscalationTactics Rule #228',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1229',
    name: 'PrivilegeEscalationTactics Rule #229',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1230',
    name: 'PrivilegeEscalationTactics Rule #230',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1231',
    name: 'PrivilegeEscalationTactics Rule #231',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1232',
    name: 'PrivilegeEscalationTactics Rule #232',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1233',
    name: 'PrivilegeEscalationTactics Rule #233',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1234',
    name: 'PrivilegeEscalationTactics Rule #234',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1235',
    name: 'PrivilegeEscalationTactics Rule #235',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1236',
    name: 'PrivilegeEscalationTactics Rule #236',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1237',
    name: 'PrivilegeEscalationTactics Rule #237',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1238',
    name: 'PrivilegeEscalationTactics Rule #238',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1239',
    name: 'PrivilegeEscalationTactics Rule #239',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1240',
    name: 'PrivilegeEscalationTactics Rule #240',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1241',
    name: 'PrivilegeEscalationTactics Rule #241',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1242',
    name: 'PrivilegeEscalationTactics Rule #242',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1243',
    name: 'PrivilegeEscalationTactics Rule #243',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1244',
    name: 'PrivilegeEscalationTactics Rule #244',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1245',
    name: 'PrivilegeEscalationTactics Rule #245',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1246',
    name: 'PrivilegeEscalationTactics Rule #246',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1247',
    name: 'PrivilegeEscalationTactics Rule #247',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1248',
    name: 'PrivilegeEscalationTactics Rule #248',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1249',
    name: 'PrivilegeEscalationTactics Rule #249',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1250',
    name: 'PrivilegeEscalationTactics Rule #250',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1251',
    name: 'PrivilegeEscalationTactics Rule #251',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1252',
    name: 'PrivilegeEscalationTactics Rule #252',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1253',
    name: 'PrivilegeEscalationTactics Rule #253',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1254',
    name: 'PrivilegeEscalationTactics Rule #254',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1255',
    name: 'PrivilegeEscalationTactics Rule #255',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1256',
    name: 'PrivilegeEscalationTactics Rule #256',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1257',
    name: 'PrivilegeEscalationTactics Rule #257',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1258',
    name: 'PrivilegeEscalationTactics Rule #258',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1259',
    name: 'PrivilegeEscalationTactics Rule #259',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1260',
    name: 'PrivilegeEscalationTactics Rule #260',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1261',
    name: 'PrivilegeEscalationTactics Rule #261',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1262',
    name: 'PrivilegeEscalationTactics Rule #262',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1263',
    name: 'PrivilegeEscalationTactics Rule #263',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1264',
    name: 'PrivilegeEscalationTactics Rule #264',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1265',
    name: 'PrivilegeEscalationTactics Rule #265',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1266',
    name: 'PrivilegeEscalationTactics Rule #266',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1267',
    name: 'PrivilegeEscalationTactics Rule #267',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1268',
    name: 'PrivilegeEscalationTactics Rule #268',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1269',
    name: 'PrivilegeEscalationTactics Rule #269',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1270',
    name: 'PrivilegeEscalationTactics Rule #270',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1271',
    name: 'PrivilegeEscalationTactics Rule #271',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1272',
    name: 'PrivilegeEscalationTactics Rule #272',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1273',
    name: 'PrivilegeEscalationTactics Rule #273',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1274',
    name: 'PrivilegeEscalationTactics Rule #274',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1275',
    name: 'PrivilegeEscalationTactics Rule #275',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1276',
    name: 'PrivilegeEscalationTactics Rule #276',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1277',
    name: 'PrivilegeEscalationTactics Rule #277',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1278',
    name: 'PrivilegeEscalationTactics Rule #278',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1279',
    name: 'PrivilegeEscalationTactics Rule #279',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1280',
    name: 'PrivilegeEscalationTactics Rule #280',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1281',
    name: 'PrivilegeEscalationTactics Rule #281',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1282',
    name: 'PrivilegeEscalationTactics Rule #282',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1283',
    name: 'PrivilegeEscalationTactics Rule #283',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1284',
    name: 'PrivilegeEscalationTactics Rule #284',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1285',
    name: 'PrivilegeEscalationTactics Rule #285',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1286',
    name: 'PrivilegeEscalationTactics Rule #286',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1287',
    name: 'PrivilegeEscalationTactics Rule #287',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1288',
    name: 'PrivilegeEscalationTactics Rule #288',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1289',
    name: 'PrivilegeEscalationTactics Rule #289',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1290',
    name: 'PrivilegeEscalationTactics Rule #290',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1291',
    name: 'PrivilegeEscalationTactics Rule #291',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1292',
    name: 'PrivilegeEscalationTactics Rule #292',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1293',
    name: 'PrivilegeEscalationTactics Rule #293',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1294',
    name: 'PrivilegeEscalationTactics Rule #294',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1295',
    name: 'PrivilegeEscalationTactics Rule #295',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1296',
    name: 'PrivilegeEscalationTactics Rule #296',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1297',
    name: 'PrivilegeEscalationTactics Rule #297',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1298',
    name: 'PrivilegeEscalationTactics Rule #298',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1299',
    name: 'PrivilegeEscalationTactics Rule #299',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1300',
    name: 'PrivilegeEscalationTactics Rule #300',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1301',
    name: 'PrivilegeEscalationTactics Rule #301',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1302',
    name: 'PrivilegeEscalationTactics Rule #302',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1303',
    name: 'PrivilegeEscalationTactics Rule #303',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1304',
    name: 'PrivilegeEscalationTactics Rule #304',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1305',
    name: 'PrivilegeEscalationTactics Rule #305',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1306',
    name: 'PrivilegeEscalationTactics Rule #306',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1307',
    name: 'PrivilegeEscalationTactics Rule #307',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1308',
    name: 'PrivilegeEscalationTactics Rule #308',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1309',
    name: 'PrivilegeEscalationTactics Rule #309',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1310',
    name: 'PrivilegeEscalationTactics Rule #310',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1311',
    name: 'PrivilegeEscalationTactics Rule #311',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1312',
    name: 'PrivilegeEscalationTactics Rule #312',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1313',
    name: 'PrivilegeEscalationTactics Rule #313',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1314',
    name: 'PrivilegeEscalationTactics Rule #314',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1315',
    name: 'PrivilegeEscalationTactics Rule #315',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1316',
    name: 'PrivilegeEscalationTactics Rule #316',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1317',
    name: 'PrivilegeEscalationTactics Rule #317',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1318',
    name: 'PrivilegeEscalationTactics Rule #318',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1319',
    name: 'PrivilegeEscalationTactics Rule #319',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1320',
    name: 'PrivilegeEscalationTactics Rule #320',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1321',
    name: 'PrivilegeEscalationTactics Rule #321',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1322',
    name: 'PrivilegeEscalationTactics Rule #322',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1323',
    name: 'PrivilegeEscalationTactics Rule #323',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1324',
    name: 'PrivilegeEscalationTactics Rule #324',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1325',
    name: 'PrivilegeEscalationTactics Rule #325',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1326',
    name: 'PrivilegeEscalationTactics Rule #326',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1327',
    name: 'PrivilegeEscalationTactics Rule #327',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1328',
    name: 'PrivilegeEscalationTactics Rule #328',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1329',
    name: 'PrivilegeEscalationTactics Rule #329',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1330',
    name: 'PrivilegeEscalationTactics Rule #330',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1331',
    name: 'PrivilegeEscalationTactics Rule #331',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1332',
    name: 'PrivilegeEscalationTactics Rule #332',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1333',
    name: 'PrivilegeEscalationTactics Rule #333',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1334',
    name: 'PrivilegeEscalationTactics Rule #334',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1335',
    name: 'PrivilegeEscalationTactics Rule #335',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1336',
    name: 'PrivilegeEscalationTactics Rule #336',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1337',
    name: 'PrivilegeEscalationTactics Rule #337',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1338',
    name: 'PrivilegeEscalationTactics Rule #338',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1339',
    name: 'PrivilegeEscalationTactics Rule #339',
    category: 'and access token theft',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1340',
    name: 'PrivilegeEscalationTactics Rule #340',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1341',
    name: 'PrivilegeEscalationTactics Rule #341',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1342',
    name: 'PrivilegeEscalationTactics Rule #342',
    category: 'DLL search order hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1343',
    name: 'PrivilegeEscalationTactics Rule #343',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1344',
    name: 'PrivilegeEscalationTactics Rule #344',
    category: 'Sudo token manipulation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1345',
    name: 'PrivilegeEscalationTactics Rule #345',
    category: 'kernel exploits',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1346',
    name: 'PrivilegeEscalationTactics Rule #346',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1347',
    name: 'PrivilegeEscalationTactics Rule #347',
    category: 'and access token theft',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1348',
    name: 'PrivilegeEscalationTactics Rule #348',
    category: 'Sudo token manipulation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1349',
    name: 'PrivilegeEscalationTactics Rule #349',
    category: 'kernel exploits',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0004-T1350',
    name: 'PrivilegeEscalationTactics Rule #350',
    category: 'DLL search order hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0004_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0004_DATASET.slice(0, 20);
    return MITRE_TA0004_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
