/**
 * MITRE ATT&CK Enterprise Matrix: DefenseEvasionTactics
 * Threat Scope: Process injection, rootkit installation, AMSI bypass, and security log clearing
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

export const MITRE_TA0005_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0005-T1001',
    name: 'DefenseEvasionTactics Rule #1',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1002',
    name: 'DefenseEvasionTactics Rule #2',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1003',
    name: 'DefenseEvasionTactics Rule #3',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1004',
    name: 'DefenseEvasionTactics Rule #4',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1005',
    name: 'DefenseEvasionTactics Rule #5',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1006',
    name: 'DefenseEvasionTactics Rule #6',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1007',
    name: 'DefenseEvasionTactics Rule #7',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1008',
    name: 'DefenseEvasionTactics Rule #8',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1009',
    name: 'DefenseEvasionTactics Rule #9',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1010',
    name: 'DefenseEvasionTactics Rule #10',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1011',
    name: 'DefenseEvasionTactics Rule #11',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1012',
    name: 'DefenseEvasionTactics Rule #12',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1013',
    name: 'DefenseEvasionTactics Rule #13',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1014',
    name: 'DefenseEvasionTactics Rule #14',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1015',
    name: 'DefenseEvasionTactics Rule #15',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1016',
    name: 'DefenseEvasionTactics Rule #16',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1017',
    name: 'DefenseEvasionTactics Rule #17',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1018',
    name: 'DefenseEvasionTactics Rule #18',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1019',
    name: 'DefenseEvasionTactics Rule #19',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1020',
    name: 'DefenseEvasionTactics Rule #20',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1021',
    name: 'DefenseEvasionTactics Rule #21',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1022',
    name: 'DefenseEvasionTactics Rule #22',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1023',
    name: 'DefenseEvasionTactics Rule #23',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1024',
    name: 'DefenseEvasionTactics Rule #24',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1025',
    name: 'DefenseEvasionTactics Rule #25',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1026',
    name: 'DefenseEvasionTactics Rule #26',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1027',
    name: 'DefenseEvasionTactics Rule #27',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1028',
    name: 'DefenseEvasionTactics Rule #28',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1029',
    name: 'DefenseEvasionTactics Rule #29',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1030',
    name: 'DefenseEvasionTactics Rule #30',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1031',
    name: 'DefenseEvasionTactics Rule #31',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1032',
    name: 'DefenseEvasionTactics Rule #32',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1033',
    name: 'DefenseEvasionTactics Rule #33',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1034',
    name: 'DefenseEvasionTactics Rule #34',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1035',
    name: 'DefenseEvasionTactics Rule #35',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1036',
    name: 'DefenseEvasionTactics Rule #36',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1037',
    name: 'DefenseEvasionTactics Rule #37',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1038',
    name: 'DefenseEvasionTactics Rule #38',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1039',
    name: 'DefenseEvasionTactics Rule #39',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1040',
    name: 'DefenseEvasionTactics Rule #40',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1041',
    name: 'DefenseEvasionTactics Rule #41',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1042',
    name: 'DefenseEvasionTactics Rule #42',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1043',
    name: 'DefenseEvasionTactics Rule #43',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1044',
    name: 'DefenseEvasionTactics Rule #44',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1045',
    name: 'DefenseEvasionTactics Rule #45',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1046',
    name: 'DefenseEvasionTactics Rule #46',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1047',
    name: 'DefenseEvasionTactics Rule #47',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1048',
    name: 'DefenseEvasionTactics Rule #48',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1049',
    name: 'DefenseEvasionTactics Rule #49',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1050',
    name: 'DefenseEvasionTactics Rule #50',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1051',
    name: 'DefenseEvasionTactics Rule #51',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1052',
    name: 'DefenseEvasionTactics Rule #52',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1053',
    name: 'DefenseEvasionTactics Rule #53',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1054',
    name: 'DefenseEvasionTactics Rule #54',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1055',
    name: 'DefenseEvasionTactics Rule #55',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1056',
    name: 'DefenseEvasionTactics Rule #56',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1057',
    name: 'DefenseEvasionTactics Rule #57',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1058',
    name: 'DefenseEvasionTactics Rule #58',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1059',
    name: 'DefenseEvasionTactics Rule #59',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1060',
    name: 'DefenseEvasionTactics Rule #60',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1061',
    name: 'DefenseEvasionTactics Rule #61',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1062',
    name: 'DefenseEvasionTactics Rule #62',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1063',
    name: 'DefenseEvasionTactics Rule #63',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1064',
    name: 'DefenseEvasionTactics Rule #64',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1065',
    name: 'DefenseEvasionTactics Rule #65',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1066',
    name: 'DefenseEvasionTactics Rule #66',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1067',
    name: 'DefenseEvasionTactics Rule #67',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1068',
    name: 'DefenseEvasionTactics Rule #68',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1069',
    name: 'DefenseEvasionTactics Rule #69',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1070',
    name: 'DefenseEvasionTactics Rule #70',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1071',
    name: 'DefenseEvasionTactics Rule #71',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1072',
    name: 'DefenseEvasionTactics Rule #72',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1073',
    name: 'DefenseEvasionTactics Rule #73',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1074',
    name: 'DefenseEvasionTactics Rule #74',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1075',
    name: 'DefenseEvasionTactics Rule #75',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1076',
    name: 'DefenseEvasionTactics Rule #76',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1077',
    name: 'DefenseEvasionTactics Rule #77',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1078',
    name: 'DefenseEvasionTactics Rule #78',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1079',
    name: 'DefenseEvasionTactics Rule #79',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1080',
    name: 'DefenseEvasionTactics Rule #80',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1081',
    name: 'DefenseEvasionTactics Rule #81',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1082',
    name: 'DefenseEvasionTactics Rule #82',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1083',
    name: 'DefenseEvasionTactics Rule #83',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1084',
    name: 'DefenseEvasionTactics Rule #84',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1085',
    name: 'DefenseEvasionTactics Rule #85',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1086',
    name: 'DefenseEvasionTactics Rule #86',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1087',
    name: 'DefenseEvasionTactics Rule #87',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1088',
    name: 'DefenseEvasionTactics Rule #88',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1089',
    name: 'DefenseEvasionTactics Rule #89',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1090',
    name: 'DefenseEvasionTactics Rule #90',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1091',
    name: 'DefenseEvasionTactics Rule #91',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1092',
    name: 'DefenseEvasionTactics Rule #92',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1093',
    name: 'DefenseEvasionTactics Rule #93',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1094',
    name: 'DefenseEvasionTactics Rule #94',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1095',
    name: 'DefenseEvasionTactics Rule #95',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1096',
    name: 'DefenseEvasionTactics Rule #96',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1097',
    name: 'DefenseEvasionTactics Rule #97',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1098',
    name: 'DefenseEvasionTactics Rule #98',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1099',
    name: 'DefenseEvasionTactics Rule #99',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1100',
    name: 'DefenseEvasionTactics Rule #100',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1101',
    name: 'DefenseEvasionTactics Rule #101',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1102',
    name: 'DefenseEvasionTactics Rule #102',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1103',
    name: 'DefenseEvasionTactics Rule #103',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1104',
    name: 'DefenseEvasionTactics Rule #104',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1105',
    name: 'DefenseEvasionTactics Rule #105',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1106',
    name: 'DefenseEvasionTactics Rule #106',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1107',
    name: 'DefenseEvasionTactics Rule #107',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1108',
    name: 'DefenseEvasionTactics Rule #108',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1109',
    name: 'DefenseEvasionTactics Rule #109',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1110',
    name: 'DefenseEvasionTactics Rule #110',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1111',
    name: 'DefenseEvasionTactics Rule #111',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1112',
    name: 'DefenseEvasionTactics Rule #112',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1113',
    name: 'DefenseEvasionTactics Rule #113',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1114',
    name: 'DefenseEvasionTactics Rule #114',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1115',
    name: 'DefenseEvasionTactics Rule #115',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1116',
    name: 'DefenseEvasionTactics Rule #116',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1117',
    name: 'DefenseEvasionTactics Rule #117',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1118',
    name: 'DefenseEvasionTactics Rule #118',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1119',
    name: 'DefenseEvasionTactics Rule #119',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1120',
    name: 'DefenseEvasionTactics Rule #120',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1121',
    name: 'DefenseEvasionTactics Rule #121',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1122',
    name: 'DefenseEvasionTactics Rule #122',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1123',
    name: 'DefenseEvasionTactics Rule #123',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1124',
    name: 'DefenseEvasionTactics Rule #124',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1125',
    name: 'DefenseEvasionTactics Rule #125',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1126',
    name: 'DefenseEvasionTactics Rule #126',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1127',
    name: 'DefenseEvasionTactics Rule #127',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1128',
    name: 'DefenseEvasionTactics Rule #128',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1129',
    name: 'DefenseEvasionTactics Rule #129',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1130',
    name: 'DefenseEvasionTactics Rule #130',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1131',
    name: 'DefenseEvasionTactics Rule #131',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1132',
    name: 'DefenseEvasionTactics Rule #132',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1133',
    name: 'DefenseEvasionTactics Rule #133',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1134',
    name: 'DefenseEvasionTactics Rule #134',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1135',
    name: 'DefenseEvasionTactics Rule #135',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1136',
    name: 'DefenseEvasionTactics Rule #136',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1137',
    name: 'DefenseEvasionTactics Rule #137',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1138',
    name: 'DefenseEvasionTactics Rule #138',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1139',
    name: 'DefenseEvasionTactics Rule #139',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1140',
    name: 'DefenseEvasionTactics Rule #140',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1141',
    name: 'DefenseEvasionTactics Rule #141',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1142',
    name: 'DefenseEvasionTactics Rule #142',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1143',
    name: 'DefenseEvasionTactics Rule #143',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1144',
    name: 'DefenseEvasionTactics Rule #144',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1145',
    name: 'DefenseEvasionTactics Rule #145',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1146',
    name: 'DefenseEvasionTactics Rule #146',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1147',
    name: 'DefenseEvasionTactics Rule #147',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1148',
    name: 'DefenseEvasionTactics Rule #148',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1149',
    name: 'DefenseEvasionTactics Rule #149',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1150',
    name: 'DefenseEvasionTactics Rule #150',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1151',
    name: 'DefenseEvasionTactics Rule #151',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1152',
    name: 'DefenseEvasionTactics Rule #152',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1153',
    name: 'DefenseEvasionTactics Rule #153',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1154',
    name: 'DefenseEvasionTactics Rule #154',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1155',
    name: 'DefenseEvasionTactics Rule #155',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1156',
    name: 'DefenseEvasionTactics Rule #156',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1157',
    name: 'DefenseEvasionTactics Rule #157',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1158',
    name: 'DefenseEvasionTactics Rule #158',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1159',
    name: 'DefenseEvasionTactics Rule #159',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1160',
    name: 'DefenseEvasionTactics Rule #160',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1161',
    name: 'DefenseEvasionTactics Rule #161',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1162',
    name: 'DefenseEvasionTactics Rule #162',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1163',
    name: 'DefenseEvasionTactics Rule #163',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1164',
    name: 'DefenseEvasionTactics Rule #164',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1165',
    name: 'DefenseEvasionTactics Rule #165',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1166',
    name: 'DefenseEvasionTactics Rule #166',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1167',
    name: 'DefenseEvasionTactics Rule #167',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1168',
    name: 'DefenseEvasionTactics Rule #168',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1169',
    name: 'DefenseEvasionTactics Rule #169',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1170',
    name: 'DefenseEvasionTactics Rule #170',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1171',
    name: 'DefenseEvasionTactics Rule #171',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1172',
    name: 'DefenseEvasionTactics Rule #172',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1173',
    name: 'DefenseEvasionTactics Rule #173',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1174',
    name: 'DefenseEvasionTactics Rule #174',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1175',
    name: 'DefenseEvasionTactics Rule #175',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1176',
    name: 'DefenseEvasionTactics Rule #176',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1177',
    name: 'DefenseEvasionTactics Rule #177',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1178',
    name: 'DefenseEvasionTactics Rule #178',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1179',
    name: 'DefenseEvasionTactics Rule #179',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1180',
    name: 'DefenseEvasionTactics Rule #180',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1181',
    name: 'DefenseEvasionTactics Rule #181',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1182',
    name: 'DefenseEvasionTactics Rule #182',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1183',
    name: 'DefenseEvasionTactics Rule #183',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1184',
    name: 'DefenseEvasionTactics Rule #184',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1185',
    name: 'DefenseEvasionTactics Rule #185',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1186',
    name: 'DefenseEvasionTactics Rule #186',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1187',
    name: 'DefenseEvasionTactics Rule #187',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1188',
    name: 'DefenseEvasionTactics Rule #188',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1189',
    name: 'DefenseEvasionTactics Rule #189',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1190',
    name: 'DefenseEvasionTactics Rule #190',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1191',
    name: 'DefenseEvasionTactics Rule #191',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1192',
    name: 'DefenseEvasionTactics Rule #192',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1193',
    name: 'DefenseEvasionTactics Rule #193',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1194',
    name: 'DefenseEvasionTactics Rule #194',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1195',
    name: 'DefenseEvasionTactics Rule #195',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1196',
    name: 'DefenseEvasionTactics Rule #196',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1197',
    name: 'DefenseEvasionTactics Rule #197',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1198',
    name: 'DefenseEvasionTactics Rule #198',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1199',
    name: 'DefenseEvasionTactics Rule #199',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1200',
    name: 'DefenseEvasionTactics Rule #200',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1201',
    name: 'DefenseEvasionTactics Rule #201',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1202',
    name: 'DefenseEvasionTactics Rule #202',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1203',
    name: 'DefenseEvasionTactics Rule #203',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1204',
    name: 'DefenseEvasionTactics Rule #204',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1205',
    name: 'DefenseEvasionTactics Rule #205',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1206',
    name: 'DefenseEvasionTactics Rule #206',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1207',
    name: 'DefenseEvasionTactics Rule #207',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1208',
    name: 'DefenseEvasionTactics Rule #208',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1209',
    name: 'DefenseEvasionTactics Rule #209',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1210',
    name: 'DefenseEvasionTactics Rule #210',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1211',
    name: 'DefenseEvasionTactics Rule #211',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1212',
    name: 'DefenseEvasionTactics Rule #212',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1213',
    name: 'DefenseEvasionTactics Rule #213',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1214',
    name: 'DefenseEvasionTactics Rule #214',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1215',
    name: 'DefenseEvasionTactics Rule #215',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1216',
    name: 'DefenseEvasionTactics Rule #216',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1217',
    name: 'DefenseEvasionTactics Rule #217',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1218',
    name: 'DefenseEvasionTactics Rule #218',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1219',
    name: 'DefenseEvasionTactics Rule #219',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1220',
    name: 'DefenseEvasionTactics Rule #220',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1221',
    name: 'DefenseEvasionTactics Rule #221',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1222',
    name: 'DefenseEvasionTactics Rule #222',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1223',
    name: 'DefenseEvasionTactics Rule #223',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1224',
    name: 'DefenseEvasionTactics Rule #224',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1225',
    name: 'DefenseEvasionTactics Rule #225',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1226',
    name: 'DefenseEvasionTactics Rule #226',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1227',
    name: 'DefenseEvasionTactics Rule #227',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1228',
    name: 'DefenseEvasionTactics Rule #228',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1229',
    name: 'DefenseEvasionTactics Rule #229',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1230',
    name: 'DefenseEvasionTactics Rule #230',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1231',
    name: 'DefenseEvasionTactics Rule #231',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1232',
    name: 'DefenseEvasionTactics Rule #232',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1233',
    name: 'DefenseEvasionTactics Rule #233',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1234',
    name: 'DefenseEvasionTactics Rule #234',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1235',
    name: 'DefenseEvasionTactics Rule #235',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1236',
    name: 'DefenseEvasionTactics Rule #236',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1237',
    name: 'DefenseEvasionTactics Rule #237',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1238',
    name: 'DefenseEvasionTactics Rule #238',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1239',
    name: 'DefenseEvasionTactics Rule #239',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1240',
    name: 'DefenseEvasionTactics Rule #240',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1241',
    name: 'DefenseEvasionTactics Rule #241',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1242',
    name: 'DefenseEvasionTactics Rule #242',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1243',
    name: 'DefenseEvasionTactics Rule #243',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1244',
    name: 'DefenseEvasionTactics Rule #244',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1245',
    name: 'DefenseEvasionTactics Rule #245',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1246',
    name: 'DefenseEvasionTactics Rule #246',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1247',
    name: 'DefenseEvasionTactics Rule #247',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1248',
    name: 'DefenseEvasionTactics Rule #248',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1249',
    name: 'DefenseEvasionTactics Rule #249',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1250',
    name: 'DefenseEvasionTactics Rule #250',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1251',
    name: 'DefenseEvasionTactics Rule #251',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1252',
    name: 'DefenseEvasionTactics Rule #252',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1253',
    name: 'DefenseEvasionTactics Rule #253',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1254',
    name: 'DefenseEvasionTactics Rule #254',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1255',
    name: 'DefenseEvasionTactics Rule #255',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1256',
    name: 'DefenseEvasionTactics Rule #256',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1257',
    name: 'DefenseEvasionTactics Rule #257',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1258',
    name: 'DefenseEvasionTactics Rule #258',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1259',
    name: 'DefenseEvasionTactics Rule #259',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1260',
    name: 'DefenseEvasionTactics Rule #260',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1261',
    name: 'DefenseEvasionTactics Rule #261',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1262',
    name: 'DefenseEvasionTactics Rule #262',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1263',
    name: 'DefenseEvasionTactics Rule #263',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1264',
    name: 'DefenseEvasionTactics Rule #264',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1265',
    name: 'DefenseEvasionTactics Rule #265',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1266',
    name: 'DefenseEvasionTactics Rule #266',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1267',
    name: 'DefenseEvasionTactics Rule #267',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1268',
    name: 'DefenseEvasionTactics Rule #268',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1269',
    name: 'DefenseEvasionTactics Rule #269',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1270',
    name: 'DefenseEvasionTactics Rule #270',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1271',
    name: 'DefenseEvasionTactics Rule #271',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1272',
    name: 'DefenseEvasionTactics Rule #272',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1273',
    name: 'DefenseEvasionTactics Rule #273',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1274',
    name: 'DefenseEvasionTactics Rule #274',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1275',
    name: 'DefenseEvasionTactics Rule #275',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1276',
    name: 'DefenseEvasionTactics Rule #276',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1277',
    name: 'DefenseEvasionTactics Rule #277',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1278',
    name: 'DefenseEvasionTactics Rule #278',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1279',
    name: 'DefenseEvasionTactics Rule #279',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1280',
    name: 'DefenseEvasionTactics Rule #280',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1281',
    name: 'DefenseEvasionTactics Rule #281',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1282',
    name: 'DefenseEvasionTactics Rule #282',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1283',
    name: 'DefenseEvasionTactics Rule #283',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1284',
    name: 'DefenseEvasionTactics Rule #284',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1285',
    name: 'DefenseEvasionTactics Rule #285',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1286',
    name: 'DefenseEvasionTactics Rule #286',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1287',
    name: 'DefenseEvasionTactics Rule #287',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1288',
    name: 'DefenseEvasionTactics Rule #288',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1289',
    name: 'DefenseEvasionTactics Rule #289',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1290',
    name: 'DefenseEvasionTactics Rule #290',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1291',
    name: 'DefenseEvasionTactics Rule #291',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1292',
    name: 'DefenseEvasionTactics Rule #292',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1293',
    name: 'DefenseEvasionTactics Rule #293',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1294',
    name: 'DefenseEvasionTactics Rule #294',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1295',
    name: 'DefenseEvasionTactics Rule #295',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1296',
    name: 'DefenseEvasionTactics Rule #296',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1297',
    name: 'DefenseEvasionTactics Rule #297',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1298',
    name: 'DefenseEvasionTactics Rule #298',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1299',
    name: 'DefenseEvasionTactics Rule #299',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1300',
    name: 'DefenseEvasionTactics Rule #300',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1301',
    name: 'DefenseEvasionTactics Rule #301',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1302',
    name: 'DefenseEvasionTactics Rule #302',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1303',
    name: 'DefenseEvasionTactics Rule #303',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1304',
    name: 'DefenseEvasionTactics Rule #304',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1305',
    name: 'DefenseEvasionTactics Rule #305',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1306',
    name: 'DefenseEvasionTactics Rule #306',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1307',
    name: 'DefenseEvasionTactics Rule #307',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1308',
    name: 'DefenseEvasionTactics Rule #308',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1309',
    name: 'DefenseEvasionTactics Rule #309',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1310',
    name: 'DefenseEvasionTactics Rule #310',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1311',
    name: 'DefenseEvasionTactics Rule #311',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1312',
    name: 'DefenseEvasionTactics Rule #312',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1313',
    name: 'DefenseEvasionTactics Rule #313',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1314',
    name: 'DefenseEvasionTactics Rule #314',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1315',
    name: 'DefenseEvasionTactics Rule #315',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1316',
    name: 'DefenseEvasionTactics Rule #316',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1317',
    name: 'DefenseEvasionTactics Rule #317',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1318',
    name: 'DefenseEvasionTactics Rule #318',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1319',
    name: 'DefenseEvasionTactics Rule #319',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1320',
    name: 'DefenseEvasionTactics Rule #320',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1321',
    name: 'DefenseEvasionTactics Rule #321',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1322',
    name: 'DefenseEvasionTactics Rule #322',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1323',
    name: 'DefenseEvasionTactics Rule #323',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1324',
    name: 'DefenseEvasionTactics Rule #324',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1325',
    name: 'DefenseEvasionTactics Rule #325',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1326',
    name: 'DefenseEvasionTactics Rule #326',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1327',
    name: 'DefenseEvasionTactics Rule #327',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1328',
    name: 'DefenseEvasionTactics Rule #328',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1329',
    name: 'DefenseEvasionTactics Rule #329',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1330',
    name: 'DefenseEvasionTactics Rule #330',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1331',
    name: 'DefenseEvasionTactics Rule #331',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1332',
    name: 'DefenseEvasionTactics Rule #332',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1333',
    name: 'DefenseEvasionTactics Rule #333',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1334',
    name: 'DefenseEvasionTactics Rule #334',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1335',
    name: 'DefenseEvasionTactics Rule #335',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1336',
    name: 'DefenseEvasionTactics Rule #336',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1337',
    name: 'DefenseEvasionTactics Rule #337',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1338',
    name: 'DefenseEvasionTactics Rule #338',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1339',
    name: 'DefenseEvasionTactics Rule #339',
    category: 'and security log clearing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1340',
    name: 'DefenseEvasionTactics Rule #340',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1341',
    name: 'DefenseEvasionTactics Rule #341',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1342',
    name: 'DefenseEvasionTactics Rule #342',
    category: 'AMSI bypass',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1343',
    name: 'DefenseEvasionTactics Rule #343',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1344',
    name: 'DefenseEvasionTactics Rule #344',
    category: 'Process injection',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1345',
    name: 'DefenseEvasionTactics Rule #345',
    category: 'rootkit installation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1346',
    name: 'DefenseEvasionTactics Rule #346',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1347',
    name: 'DefenseEvasionTactics Rule #347',
    category: 'and security log clearing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1348',
    name: 'DefenseEvasionTactics Rule #348',
    category: 'Process injection',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1349',
    name: 'DefenseEvasionTactics Rule #349',
    category: 'rootkit installation',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0005-T1350',
    name: 'DefenseEvasionTactics Rule #350',
    category: 'AMSI bypass',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0005_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0005_DATASET.slice(0, 20);
    return MITRE_TA0005_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
