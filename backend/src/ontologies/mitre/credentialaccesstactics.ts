/**
 * MITRE ATT&CK Enterprise Matrix: CredentialAccessTactics
 * Threat Scope: LSASS memory dumping, Kerberoasting, NTDS.dit extraction, and credential stuffing
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

export const MITRE_TA0006_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0006-T1001',
    name: 'CredentialAccessTactics Rule #1',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1002',
    name: 'CredentialAccessTactics Rule #2',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1003',
    name: 'CredentialAccessTactics Rule #3',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1004',
    name: 'CredentialAccessTactics Rule #4',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1005',
    name: 'CredentialAccessTactics Rule #5',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1006',
    name: 'CredentialAccessTactics Rule #6',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1007',
    name: 'CredentialAccessTactics Rule #7',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1008',
    name: 'CredentialAccessTactics Rule #8',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1009',
    name: 'CredentialAccessTactics Rule #9',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1010',
    name: 'CredentialAccessTactics Rule #10',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1011',
    name: 'CredentialAccessTactics Rule #11',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1012',
    name: 'CredentialAccessTactics Rule #12',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1013',
    name: 'CredentialAccessTactics Rule #13',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1014',
    name: 'CredentialAccessTactics Rule #14',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1015',
    name: 'CredentialAccessTactics Rule #15',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1016',
    name: 'CredentialAccessTactics Rule #16',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1017',
    name: 'CredentialAccessTactics Rule #17',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1018',
    name: 'CredentialAccessTactics Rule #18',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1019',
    name: 'CredentialAccessTactics Rule #19',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1020',
    name: 'CredentialAccessTactics Rule #20',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1021',
    name: 'CredentialAccessTactics Rule #21',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1022',
    name: 'CredentialAccessTactics Rule #22',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1023',
    name: 'CredentialAccessTactics Rule #23',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1024',
    name: 'CredentialAccessTactics Rule #24',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1025',
    name: 'CredentialAccessTactics Rule #25',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1026',
    name: 'CredentialAccessTactics Rule #26',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1027',
    name: 'CredentialAccessTactics Rule #27',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1028',
    name: 'CredentialAccessTactics Rule #28',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1029',
    name: 'CredentialAccessTactics Rule #29',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1030',
    name: 'CredentialAccessTactics Rule #30',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1031',
    name: 'CredentialAccessTactics Rule #31',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1032',
    name: 'CredentialAccessTactics Rule #32',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1033',
    name: 'CredentialAccessTactics Rule #33',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1034',
    name: 'CredentialAccessTactics Rule #34',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1035',
    name: 'CredentialAccessTactics Rule #35',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1036',
    name: 'CredentialAccessTactics Rule #36',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1037',
    name: 'CredentialAccessTactics Rule #37',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1038',
    name: 'CredentialAccessTactics Rule #38',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1039',
    name: 'CredentialAccessTactics Rule #39',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1040',
    name: 'CredentialAccessTactics Rule #40',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1041',
    name: 'CredentialAccessTactics Rule #41',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1042',
    name: 'CredentialAccessTactics Rule #42',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1043',
    name: 'CredentialAccessTactics Rule #43',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1044',
    name: 'CredentialAccessTactics Rule #44',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1045',
    name: 'CredentialAccessTactics Rule #45',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1046',
    name: 'CredentialAccessTactics Rule #46',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1047',
    name: 'CredentialAccessTactics Rule #47',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1048',
    name: 'CredentialAccessTactics Rule #48',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1049',
    name: 'CredentialAccessTactics Rule #49',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1050',
    name: 'CredentialAccessTactics Rule #50',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1051',
    name: 'CredentialAccessTactics Rule #51',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1052',
    name: 'CredentialAccessTactics Rule #52',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1053',
    name: 'CredentialAccessTactics Rule #53',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1054',
    name: 'CredentialAccessTactics Rule #54',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1055',
    name: 'CredentialAccessTactics Rule #55',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1056',
    name: 'CredentialAccessTactics Rule #56',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1057',
    name: 'CredentialAccessTactics Rule #57',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1058',
    name: 'CredentialAccessTactics Rule #58',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1059',
    name: 'CredentialAccessTactics Rule #59',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1060',
    name: 'CredentialAccessTactics Rule #60',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1061',
    name: 'CredentialAccessTactics Rule #61',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1062',
    name: 'CredentialAccessTactics Rule #62',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1063',
    name: 'CredentialAccessTactics Rule #63',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1064',
    name: 'CredentialAccessTactics Rule #64',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1065',
    name: 'CredentialAccessTactics Rule #65',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1066',
    name: 'CredentialAccessTactics Rule #66',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1067',
    name: 'CredentialAccessTactics Rule #67',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1068',
    name: 'CredentialAccessTactics Rule #68',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1069',
    name: 'CredentialAccessTactics Rule #69',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1070',
    name: 'CredentialAccessTactics Rule #70',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1071',
    name: 'CredentialAccessTactics Rule #71',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1072',
    name: 'CredentialAccessTactics Rule #72',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1073',
    name: 'CredentialAccessTactics Rule #73',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1074',
    name: 'CredentialAccessTactics Rule #74',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1075',
    name: 'CredentialAccessTactics Rule #75',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1076',
    name: 'CredentialAccessTactics Rule #76',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1077',
    name: 'CredentialAccessTactics Rule #77',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1078',
    name: 'CredentialAccessTactics Rule #78',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1079',
    name: 'CredentialAccessTactics Rule #79',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1080',
    name: 'CredentialAccessTactics Rule #80',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1081',
    name: 'CredentialAccessTactics Rule #81',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1082',
    name: 'CredentialAccessTactics Rule #82',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1083',
    name: 'CredentialAccessTactics Rule #83',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1084',
    name: 'CredentialAccessTactics Rule #84',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1085',
    name: 'CredentialAccessTactics Rule #85',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1086',
    name: 'CredentialAccessTactics Rule #86',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1087',
    name: 'CredentialAccessTactics Rule #87',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1088',
    name: 'CredentialAccessTactics Rule #88',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1089',
    name: 'CredentialAccessTactics Rule #89',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1090',
    name: 'CredentialAccessTactics Rule #90',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1091',
    name: 'CredentialAccessTactics Rule #91',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1092',
    name: 'CredentialAccessTactics Rule #92',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1093',
    name: 'CredentialAccessTactics Rule #93',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1094',
    name: 'CredentialAccessTactics Rule #94',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1095',
    name: 'CredentialAccessTactics Rule #95',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1096',
    name: 'CredentialAccessTactics Rule #96',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1097',
    name: 'CredentialAccessTactics Rule #97',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1098',
    name: 'CredentialAccessTactics Rule #98',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1099',
    name: 'CredentialAccessTactics Rule #99',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1100',
    name: 'CredentialAccessTactics Rule #100',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1101',
    name: 'CredentialAccessTactics Rule #101',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1102',
    name: 'CredentialAccessTactics Rule #102',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1103',
    name: 'CredentialAccessTactics Rule #103',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1104',
    name: 'CredentialAccessTactics Rule #104',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1105',
    name: 'CredentialAccessTactics Rule #105',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1106',
    name: 'CredentialAccessTactics Rule #106',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1107',
    name: 'CredentialAccessTactics Rule #107',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1108',
    name: 'CredentialAccessTactics Rule #108',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1109',
    name: 'CredentialAccessTactics Rule #109',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1110',
    name: 'CredentialAccessTactics Rule #110',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1111',
    name: 'CredentialAccessTactics Rule #111',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1112',
    name: 'CredentialAccessTactics Rule #112',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1113',
    name: 'CredentialAccessTactics Rule #113',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1114',
    name: 'CredentialAccessTactics Rule #114',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1115',
    name: 'CredentialAccessTactics Rule #115',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1116',
    name: 'CredentialAccessTactics Rule #116',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1117',
    name: 'CredentialAccessTactics Rule #117',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1118',
    name: 'CredentialAccessTactics Rule #118',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1119',
    name: 'CredentialAccessTactics Rule #119',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1120',
    name: 'CredentialAccessTactics Rule #120',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1121',
    name: 'CredentialAccessTactics Rule #121',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1122',
    name: 'CredentialAccessTactics Rule #122',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1123',
    name: 'CredentialAccessTactics Rule #123',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1124',
    name: 'CredentialAccessTactics Rule #124',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1125',
    name: 'CredentialAccessTactics Rule #125',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1126',
    name: 'CredentialAccessTactics Rule #126',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1127',
    name: 'CredentialAccessTactics Rule #127',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1128',
    name: 'CredentialAccessTactics Rule #128',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1129',
    name: 'CredentialAccessTactics Rule #129',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1130',
    name: 'CredentialAccessTactics Rule #130',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1131',
    name: 'CredentialAccessTactics Rule #131',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1132',
    name: 'CredentialAccessTactics Rule #132',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1133',
    name: 'CredentialAccessTactics Rule #133',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1134',
    name: 'CredentialAccessTactics Rule #134',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1135',
    name: 'CredentialAccessTactics Rule #135',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1136',
    name: 'CredentialAccessTactics Rule #136',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1137',
    name: 'CredentialAccessTactics Rule #137',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1138',
    name: 'CredentialAccessTactics Rule #138',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1139',
    name: 'CredentialAccessTactics Rule #139',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1140',
    name: 'CredentialAccessTactics Rule #140',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1141',
    name: 'CredentialAccessTactics Rule #141',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1142',
    name: 'CredentialAccessTactics Rule #142',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1143',
    name: 'CredentialAccessTactics Rule #143',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1144',
    name: 'CredentialAccessTactics Rule #144',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1145',
    name: 'CredentialAccessTactics Rule #145',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1146',
    name: 'CredentialAccessTactics Rule #146',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1147',
    name: 'CredentialAccessTactics Rule #147',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1148',
    name: 'CredentialAccessTactics Rule #148',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1149',
    name: 'CredentialAccessTactics Rule #149',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1150',
    name: 'CredentialAccessTactics Rule #150',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1151',
    name: 'CredentialAccessTactics Rule #151',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1152',
    name: 'CredentialAccessTactics Rule #152',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1153',
    name: 'CredentialAccessTactics Rule #153',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1154',
    name: 'CredentialAccessTactics Rule #154',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1155',
    name: 'CredentialAccessTactics Rule #155',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1156',
    name: 'CredentialAccessTactics Rule #156',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1157',
    name: 'CredentialAccessTactics Rule #157',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1158',
    name: 'CredentialAccessTactics Rule #158',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1159',
    name: 'CredentialAccessTactics Rule #159',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1160',
    name: 'CredentialAccessTactics Rule #160',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1161',
    name: 'CredentialAccessTactics Rule #161',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1162',
    name: 'CredentialAccessTactics Rule #162',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1163',
    name: 'CredentialAccessTactics Rule #163',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1164',
    name: 'CredentialAccessTactics Rule #164',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1165',
    name: 'CredentialAccessTactics Rule #165',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1166',
    name: 'CredentialAccessTactics Rule #166',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1167',
    name: 'CredentialAccessTactics Rule #167',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1168',
    name: 'CredentialAccessTactics Rule #168',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1169',
    name: 'CredentialAccessTactics Rule #169',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1170',
    name: 'CredentialAccessTactics Rule #170',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1171',
    name: 'CredentialAccessTactics Rule #171',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1172',
    name: 'CredentialAccessTactics Rule #172',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1173',
    name: 'CredentialAccessTactics Rule #173',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1174',
    name: 'CredentialAccessTactics Rule #174',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1175',
    name: 'CredentialAccessTactics Rule #175',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1176',
    name: 'CredentialAccessTactics Rule #176',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1177',
    name: 'CredentialAccessTactics Rule #177',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1178',
    name: 'CredentialAccessTactics Rule #178',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1179',
    name: 'CredentialAccessTactics Rule #179',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1180',
    name: 'CredentialAccessTactics Rule #180',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1181',
    name: 'CredentialAccessTactics Rule #181',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1182',
    name: 'CredentialAccessTactics Rule #182',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1183',
    name: 'CredentialAccessTactics Rule #183',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1184',
    name: 'CredentialAccessTactics Rule #184',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1185',
    name: 'CredentialAccessTactics Rule #185',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1186',
    name: 'CredentialAccessTactics Rule #186',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1187',
    name: 'CredentialAccessTactics Rule #187',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1188',
    name: 'CredentialAccessTactics Rule #188',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1189',
    name: 'CredentialAccessTactics Rule #189',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1190',
    name: 'CredentialAccessTactics Rule #190',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1191',
    name: 'CredentialAccessTactics Rule #191',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1192',
    name: 'CredentialAccessTactics Rule #192',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1193',
    name: 'CredentialAccessTactics Rule #193',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1194',
    name: 'CredentialAccessTactics Rule #194',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1195',
    name: 'CredentialAccessTactics Rule #195',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1196',
    name: 'CredentialAccessTactics Rule #196',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1197',
    name: 'CredentialAccessTactics Rule #197',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1198',
    name: 'CredentialAccessTactics Rule #198',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1199',
    name: 'CredentialAccessTactics Rule #199',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1200',
    name: 'CredentialAccessTactics Rule #200',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1201',
    name: 'CredentialAccessTactics Rule #201',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1202',
    name: 'CredentialAccessTactics Rule #202',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1203',
    name: 'CredentialAccessTactics Rule #203',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1204',
    name: 'CredentialAccessTactics Rule #204',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1205',
    name: 'CredentialAccessTactics Rule #205',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1206',
    name: 'CredentialAccessTactics Rule #206',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1207',
    name: 'CredentialAccessTactics Rule #207',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1208',
    name: 'CredentialAccessTactics Rule #208',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1209',
    name: 'CredentialAccessTactics Rule #209',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1210',
    name: 'CredentialAccessTactics Rule #210',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1211',
    name: 'CredentialAccessTactics Rule #211',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1212',
    name: 'CredentialAccessTactics Rule #212',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1213',
    name: 'CredentialAccessTactics Rule #213',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1214',
    name: 'CredentialAccessTactics Rule #214',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1215',
    name: 'CredentialAccessTactics Rule #215',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1216',
    name: 'CredentialAccessTactics Rule #216',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1217',
    name: 'CredentialAccessTactics Rule #217',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1218',
    name: 'CredentialAccessTactics Rule #218',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1219',
    name: 'CredentialAccessTactics Rule #219',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1220',
    name: 'CredentialAccessTactics Rule #220',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1221',
    name: 'CredentialAccessTactics Rule #221',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1222',
    name: 'CredentialAccessTactics Rule #222',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1223',
    name: 'CredentialAccessTactics Rule #223',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1224',
    name: 'CredentialAccessTactics Rule #224',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1225',
    name: 'CredentialAccessTactics Rule #225',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1226',
    name: 'CredentialAccessTactics Rule #226',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1227',
    name: 'CredentialAccessTactics Rule #227',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1228',
    name: 'CredentialAccessTactics Rule #228',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1229',
    name: 'CredentialAccessTactics Rule #229',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1230',
    name: 'CredentialAccessTactics Rule #230',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1231',
    name: 'CredentialAccessTactics Rule #231',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1232',
    name: 'CredentialAccessTactics Rule #232',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1233',
    name: 'CredentialAccessTactics Rule #233',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1234',
    name: 'CredentialAccessTactics Rule #234',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1235',
    name: 'CredentialAccessTactics Rule #235',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1236',
    name: 'CredentialAccessTactics Rule #236',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1237',
    name: 'CredentialAccessTactics Rule #237',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1238',
    name: 'CredentialAccessTactics Rule #238',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1239',
    name: 'CredentialAccessTactics Rule #239',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1240',
    name: 'CredentialAccessTactics Rule #240',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1241',
    name: 'CredentialAccessTactics Rule #241',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1242',
    name: 'CredentialAccessTactics Rule #242',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1243',
    name: 'CredentialAccessTactics Rule #243',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1244',
    name: 'CredentialAccessTactics Rule #244',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1245',
    name: 'CredentialAccessTactics Rule #245',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1246',
    name: 'CredentialAccessTactics Rule #246',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1247',
    name: 'CredentialAccessTactics Rule #247',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1248',
    name: 'CredentialAccessTactics Rule #248',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1249',
    name: 'CredentialAccessTactics Rule #249',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1250',
    name: 'CredentialAccessTactics Rule #250',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1251',
    name: 'CredentialAccessTactics Rule #251',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1252',
    name: 'CredentialAccessTactics Rule #252',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1253',
    name: 'CredentialAccessTactics Rule #253',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1254',
    name: 'CredentialAccessTactics Rule #254',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1255',
    name: 'CredentialAccessTactics Rule #255',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1256',
    name: 'CredentialAccessTactics Rule #256',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1257',
    name: 'CredentialAccessTactics Rule #257',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1258',
    name: 'CredentialAccessTactics Rule #258',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1259',
    name: 'CredentialAccessTactics Rule #259',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1260',
    name: 'CredentialAccessTactics Rule #260',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1261',
    name: 'CredentialAccessTactics Rule #261',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1262',
    name: 'CredentialAccessTactics Rule #262',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1263',
    name: 'CredentialAccessTactics Rule #263',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1264',
    name: 'CredentialAccessTactics Rule #264',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1265',
    name: 'CredentialAccessTactics Rule #265',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1266',
    name: 'CredentialAccessTactics Rule #266',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1267',
    name: 'CredentialAccessTactics Rule #267',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1268',
    name: 'CredentialAccessTactics Rule #268',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1269',
    name: 'CredentialAccessTactics Rule #269',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1270',
    name: 'CredentialAccessTactics Rule #270',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1271',
    name: 'CredentialAccessTactics Rule #271',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1272',
    name: 'CredentialAccessTactics Rule #272',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1273',
    name: 'CredentialAccessTactics Rule #273',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1274',
    name: 'CredentialAccessTactics Rule #274',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1275',
    name: 'CredentialAccessTactics Rule #275',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1276',
    name: 'CredentialAccessTactics Rule #276',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1277',
    name: 'CredentialAccessTactics Rule #277',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1278',
    name: 'CredentialAccessTactics Rule #278',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1279',
    name: 'CredentialAccessTactics Rule #279',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1280',
    name: 'CredentialAccessTactics Rule #280',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1281',
    name: 'CredentialAccessTactics Rule #281',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1282',
    name: 'CredentialAccessTactics Rule #282',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1283',
    name: 'CredentialAccessTactics Rule #283',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1284',
    name: 'CredentialAccessTactics Rule #284',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1285',
    name: 'CredentialAccessTactics Rule #285',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1286',
    name: 'CredentialAccessTactics Rule #286',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1287',
    name: 'CredentialAccessTactics Rule #287',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1288',
    name: 'CredentialAccessTactics Rule #288',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1289',
    name: 'CredentialAccessTactics Rule #289',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1290',
    name: 'CredentialAccessTactics Rule #290',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1291',
    name: 'CredentialAccessTactics Rule #291',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1292',
    name: 'CredentialAccessTactics Rule #292',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1293',
    name: 'CredentialAccessTactics Rule #293',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1294',
    name: 'CredentialAccessTactics Rule #294',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1295',
    name: 'CredentialAccessTactics Rule #295',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1296',
    name: 'CredentialAccessTactics Rule #296',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1297',
    name: 'CredentialAccessTactics Rule #297',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1298',
    name: 'CredentialAccessTactics Rule #298',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1299',
    name: 'CredentialAccessTactics Rule #299',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1300',
    name: 'CredentialAccessTactics Rule #300',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1301',
    name: 'CredentialAccessTactics Rule #301',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1302',
    name: 'CredentialAccessTactics Rule #302',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1303',
    name: 'CredentialAccessTactics Rule #303',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1304',
    name: 'CredentialAccessTactics Rule #304',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1305',
    name: 'CredentialAccessTactics Rule #305',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1306',
    name: 'CredentialAccessTactics Rule #306',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1307',
    name: 'CredentialAccessTactics Rule #307',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1308',
    name: 'CredentialAccessTactics Rule #308',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1309',
    name: 'CredentialAccessTactics Rule #309',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1310',
    name: 'CredentialAccessTactics Rule #310',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1311',
    name: 'CredentialAccessTactics Rule #311',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1312',
    name: 'CredentialAccessTactics Rule #312',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1313',
    name: 'CredentialAccessTactics Rule #313',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1314',
    name: 'CredentialAccessTactics Rule #314',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1315',
    name: 'CredentialAccessTactics Rule #315',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1316',
    name: 'CredentialAccessTactics Rule #316',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1317',
    name: 'CredentialAccessTactics Rule #317',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1318',
    name: 'CredentialAccessTactics Rule #318',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1319',
    name: 'CredentialAccessTactics Rule #319',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1320',
    name: 'CredentialAccessTactics Rule #320',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1321',
    name: 'CredentialAccessTactics Rule #321',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1322',
    name: 'CredentialAccessTactics Rule #322',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1323',
    name: 'CredentialAccessTactics Rule #323',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1324',
    name: 'CredentialAccessTactics Rule #324',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1325',
    name: 'CredentialAccessTactics Rule #325',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1326',
    name: 'CredentialAccessTactics Rule #326',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1327',
    name: 'CredentialAccessTactics Rule #327',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1328',
    name: 'CredentialAccessTactics Rule #328',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1329',
    name: 'CredentialAccessTactics Rule #329',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1330',
    name: 'CredentialAccessTactics Rule #330',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1331',
    name: 'CredentialAccessTactics Rule #331',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1332',
    name: 'CredentialAccessTactics Rule #332',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1333',
    name: 'CredentialAccessTactics Rule #333',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1334',
    name: 'CredentialAccessTactics Rule #334',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1335',
    name: 'CredentialAccessTactics Rule #335',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1336',
    name: 'CredentialAccessTactics Rule #336',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1337',
    name: 'CredentialAccessTactics Rule #337',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1338',
    name: 'CredentialAccessTactics Rule #338',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1339',
    name: 'CredentialAccessTactics Rule #339',
    category: 'and credential stuffing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1340',
    name: 'CredentialAccessTactics Rule #340',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1341',
    name: 'CredentialAccessTactics Rule #341',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1342',
    name: 'CredentialAccessTactics Rule #342',
    category: 'NTDS.dit extraction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1343',
    name: 'CredentialAccessTactics Rule #343',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1344',
    name: 'CredentialAccessTactics Rule #344',
    category: 'LSASS memory dumping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1345',
    name: 'CredentialAccessTactics Rule #345',
    category: 'Kerberoasting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1346',
    name: 'CredentialAccessTactics Rule #346',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1347',
    name: 'CredentialAccessTactics Rule #347',
    category: 'and credential stuffing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1348',
    name: 'CredentialAccessTactics Rule #348',
    category: 'LSASS memory dumping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1349',
    name: 'CredentialAccessTactics Rule #349',
    category: 'Kerberoasting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0006-T1350',
    name: 'CredentialAccessTactics Rule #350',
    category: 'NTDS.dit extraction',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0006_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0006_DATASET.slice(0, 20);
    return MITRE_TA0006_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
