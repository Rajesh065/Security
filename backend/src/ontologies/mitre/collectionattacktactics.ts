/**
 * MITRE ATT&CK Enterprise Matrix: CollectionAttackTactics
 * Threat Scope: Automated data staging, clipboard monitoring, screen capture, and email harvesting
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

export const MITRE_TA0009_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0009-T1001',
    name: 'CollectionAttackTactics Rule #1',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1002',
    name: 'CollectionAttackTactics Rule #2',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1003',
    name: 'CollectionAttackTactics Rule #3',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1004',
    name: 'CollectionAttackTactics Rule #4',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1005',
    name: 'CollectionAttackTactics Rule #5',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1006',
    name: 'CollectionAttackTactics Rule #6',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1007',
    name: 'CollectionAttackTactics Rule #7',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1008',
    name: 'CollectionAttackTactics Rule #8',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1009',
    name: 'CollectionAttackTactics Rule #9',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1010',
    name: 'CollectionAttackTactics Rule #10',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1011',
    name: 'CollectionAttackTactics Rule #11',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1012',
    name: 'CollectionAttackTactics Rule #12',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1013',
    name: 'CollectionAttackTactics Rule #13',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1014',
    name: 'CollectionAttackTactics Rule #14',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1015',
    name: 'CollectionAttackTactics Rule #15',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1016',
    name: 'CollectionAttackTactics Rule #16',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1017',
    name: 'CollectionAttackTactics Rule #17',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1018',
    name: 'CollectionAttackTactics Rule #18',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1019',
    name: 'CollectionAttackTactics Rule #19',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1020',
    name: 'CollectionAttackTactics Rule #20',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1021',
    name: 'CollectionAttackTactics Rule #21',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1022',
    name: 'CollectionAttackTactics Rule #22',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1023',
    name: 'CollectionAttackTactics Rule #23',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1024',
    name: 'CollectionAttackTactics Rule #24',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1025',
    name: 'CollectionAttackTactics Rule #25',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1026',
    name: 'CollectionAttackTactics Rule #26',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1027',
    name: 'CollectionAttackTactics Rule #27',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1028',
    name: 'CollectionAttackTactics Rule #28',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1029',
    name: 'CollectionAttackTactics Rule #29',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1030',
    name: 'CollectionAttackTactics Rule #30',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1031',
    name: 'CollectionAttackTactics Rule #31',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1032',
    name: 'CollectionAttackTactics Rule #32',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1033',
    name: 'CollectionAttackTactics Rule #33',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1034',
    name: 'CollectionAttackTactics Rule #34',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1035',
    name: 'CollectionAttackTactics Rule #35',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1036',
    name: 'CollectionAttackTactics Rule #36',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1037',
    name: 'CollectionAttackTactics Rule #37',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1038',
    name: 'CollectionAttackTactics Rule #38',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1039',
    name: 'CollectionAttackTactics Rule #39',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1040',
    name: 'CollectionAttackTactics Rule #40',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1041',
    name: 'CollectionAttackTactics Rule #41',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1042',
    name: 'CollectionAttackTactics Rule #42',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1043',
    name: 'CollectionAttackTactics Rule #43',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1044',
    name: 'CollectionAttackTactics Rule #44',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1045',
    name: 'CollectionAttackTactics Rule #45',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1046',
    name: 'CollectionAttackTactics Rule #46',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1047',
    name: 'CollectionAttackTactics Rule #47',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1048',
    name: 'CollectionAttackTactics Rule #48',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1049',
    name: 'CollectionAttackTactics Rule #49',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1050',
    name: 'CollectionAttackTactics Rule #50',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1051',
    name: 'CollectionAttackTactics Rule #51',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1052',
    name: 'CollectionAttackTactics Rule #52',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1053',
    name: 'CollectionAttackTactics Rule #53',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1054',
    name: 'CollectionAttackTactics Rule #54',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1055',
    name: 'CollectionAttackTactics Rule #55',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1056',
    name: 'CollectionAttackTactics Rule #56',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1057',
    name: 'CollectionAttackTactics Rule #57',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1058',
    name: 'CollectionAttackTactics Rule #58',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1059',
    name: 'CollectionAttackTactics Rule #59',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1060',
    name: 'CollectionAttackTactics Rule #60',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1061',
    name: 'CollectionAttackTactics Rule #61',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1062',
    name: 'CollectionAttackTactics Rule #62',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1063',
    name: 'CollectionAttackTactics Rule #63',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1064',
    name: 'CollectionAttackTactics Rule #64',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1065',
    name: 'CollectionAttackTactics Rule #65',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1066',
    name: 'CollectionAttackTactics Rule #66',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1067',
    name: 'CollectionAttackTactics Rule #67',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1068',
    name: 'CollectionAttackTactics Rule #68',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1069',
    name: 'CollectionAttackTactics Rule #69',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1070',
    name: 'CollectionAttackTactics Rule #70',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1071',
    name: 'CollectionAttackTactics Rule #71',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1072',
    name: 'CollectionAttackTactics Rule #72',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1073',
    name: 'CollectionAttackTactics Rule #73',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1074',
    name: 'CollectionAttackTactics Rule #74',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1075',
    name: 'CollectionAttackTactics Rule #75',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1076',
    name: 'CollectionAttackTactics Rule #76',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1077',
    name: 'CollectionAttackTactics Rule #77',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1078',
    name: 'CollectionAttackTactics Rule #78',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1079',
    name: 'CollectionAttackTactics Rule #79',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1080',
    name: 'CollectionAttackTactics Rule #80',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1081',
    name: 'CollectionAttackTactics Rule #81',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1082',
    name: 'CollectionAttackTactics Rule #82',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1083',
    name: 'CollectionAttackTactics Rule #83',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1084',
    name: 'CollectionAttackTactics Rule #84',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1085',
    name: 'CollectionAttackTactics Rule #85',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1086',
    name: 'CollectionAttackTactics Rule #86',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1087',
    name: 'CollectionAttackTactics Rule #87',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1088',
    name: 'CollectionAttackTactics Rule #88',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1089',
    name: 'CollectionAttackTactics Rule #89',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1090',
    name: 'CollectionAttackTactics Rule #90',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1091',
    name: 'CollectionAttackTactics Rule #91',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1092',
    name: 'CollectionAttackTactics Rule #92',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1093',
    name: 'CollectionAttackTactics Rule #93',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1094',
    name: 'CollectionAttackTactics Rule #94',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1095',
    name: 'CollectionAttackTactics Rule #95',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1096',
    name: 'CollectionAttackTactics Rule #96',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1097',
    name: 'CollectionAttackTactics Rule #97',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1098',
    name: 'CollectionAttackTactics Rule #98',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1099',
    name: 'CollectionAttackTactics Rule #99',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1100',
    name: 'CollectionAttackTactics Rule #100',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1101',
    name: 'CollectionAttackTactics Rule #101',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1102',
    name: 'CollectionAttackTactics Rule #102',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1103',
    name: 'CollectionAttackTactics Rule #103',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1104',
    name: 'CollectionAttackTactics Rule #104',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1105',
    name: 'CollectionAttackTactics Rule #105',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1106',
    name: 'CollectionAttackTactics Rule #106',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1107',
    name: 'CollectionAttackTactics Rule #107',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1108',
    name: 'CollectionAttackTactics Rule #108',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1109',
    name: 'CollectionAttackTactics Rule #109',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1110',
    name: 'CollectionAttackTactics Rule #110',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1111',
    name: 'CollectionAttackTactics Rule #111',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1112',
    name: 'CollectionAttackTactics Rule #112',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1113',
    name: 'CollectionAttackTactics Rule #113',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1114',
    name: 'CollectionAttackTactics Rule #114',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1115',
    name: 'CollectionAttackTactics Rule #115',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1116',
    name: 'CollectionAttackTactics Rule #116',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1117',
    name: 'CollectionAttackTactics Rule #117',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1118',
    name: 'CollectionAttackTactics Rule #118',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1119',
    name: 'CollectionAttackTactics Rule #119',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1120',
    name: 'CollectionAttackTactics Rule #120',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1121',
    name: 'CollectionAttackTactics Rule #121',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1122',
    name: 'CollectionAttackTactics Rule #122',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1123',
    name: 'CollectionAttackTactics Rule #123',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1124',
    name: 'CollectionAttackTactics Rule #124',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1125',
    name: 'CollectionAttackTactics Rule #125',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1126',
    name: 'CollectionAttackTactics Rule #126',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1127',
    name: 'CollectionAttackTactics Rule #127',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1128',
    name: 'CollectionAttackTactics Rule #128',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1129',
    name: 'CollectionAttackTactics Rule #129',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1130',
    name: 'CollectionAttackTactics Rule #130',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1131',
    name: 'CollectionAttackTactics Rule #131',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1132',
    name: 'CollectionAttackTactics Rule #132',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1133',
    name: 'CollectionAttackTactics Rule #133',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1134',
    name: 'CollectionAttackTactics Rule #134',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1135',
    name: 'CollectionAttackTactics Rule #135',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1136',
    name: 'CollectionAttackTactics Rule #136',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1137',
    name: 'CollectionAttackTactics Rule #137',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1138',
    name: 'CollectionAttackTactics Rule #138',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1139',
    name: 'CollectionAttackTactics Rule #139',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1140',
    name: 'CollectionAttackTactics Rule #140',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1141',
    name: 'CollectionAttackTactics Rule #141',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1142',
    name: 'CollectionAttackTactics Rule #142',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1143',
    name: 'CollectionAttackTactics Rule #143',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1144',
    name: 'CollectionAttackTactics Rule #144',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1145',
    name: 'CollectionAttackTactics Rule #145',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1146',
    name: 'CollectionAttackTactics Rule #146',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1147',
    name: 'CollectionAttackTactics Rule #147',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1148',
    name: 'CollectionAttackTactics Rule #148',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1149',
    name: 'CollectionAttackTactics Rule #149',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1150',
    name: 'CollectionAttackTactics Rule #150',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1151',
    name: 'CollectionAttackTactics Rule #151',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1152',
    name: 'CollectionAttackTactics Rule #152',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1153',
    name: 'CollectionAttackTactics Rule #153',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1154',
    name: 'CollectionAttackTactics Rule #154',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1155',
    name: 'CollectionAttackTactics Rule #155',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1156',
    name: 'CollectionAttackTactics Rule #156',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1157',
    name: 'CollectionAttackTactics Rule #157',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1158',
    name: 'CollectionAttackTactics Rule #158',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1159',
    name: 'CollectionAttackTactics Rule #159',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1160',
    name: 'CollectionAttackTactics Rule #160',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1161',
    name: 'CollectionAttackTactics Rule #161',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1162',
    name: 'CollectionAttackTactics Rule #162',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1163',
    name: 'CollectionAttackTactics Rule #163',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1164',
    name: 'CollectionAttackTactics Rule #164',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1165',
    name: 'CollectionAttackTactics Rule #165',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1166',
    name: 'CollectionAttackTactics Rule #166',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1167',
    name: 'CollectionAttackTactics Rule #167',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1168',
    name: 'CollectionAttackTactics Rule #168',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1169',
    name: 'CollectionAttackTactics Rule #169',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1170',
    name: 'CollectionAttackTactics Rule #170',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1171',
    name: 'CollectionAttackTactics Rule #171',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1172',
    name: 'CollectionAttackTactics Rule #172',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1173',
    name: 'CollectionAttackTactics Rule #173',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1174',
    name: 'CollectionAttackTactics Rule #174',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1175',
    name: 'CollectionAttackTactics Rule #175',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1176',
    name: 'CollectionAttackTactics Rule #176',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1177',
    name: 'CollectionAttackTactics Rule #177',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1178',
    name: 'CollectionAttackTactics Rule #178',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1179',
    name: 'CollectionAttackTactics Rule #179',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1180',
    name: 'CollectionAttackTactics Rule #180',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1181',
    name: 'CollectionAttackTactics Rule #181',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1182',
    name: 'CollectionAttackTactics Rule #182',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1183',
    name: 'CollectionAttackTactics Rule #183',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1184',
    name: 'CollectionAttackTactics Rule #184',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1185',
    name: 'CollectionAttackTactics Rule #185',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1186',
    name: 'CollectionAttackTactics Rule #186',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1187',
    name: 'CollectionAttackTactics Rule #187',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1188',
    name: 'CollectionAttackTactics Rule #188',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1189',
    name: 'CollectionAttackTactics Rule #189',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1190',
    name: 'CollectionAttackTactics Rule #190',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1191',
    name: 'CollectionAttackTactics Rule #191',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1192',
    name: 'CollectionAttackTactics Rule #192',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1193',
    name: 'CollectionAttackTactics Rule #193',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1194',
    name: 'CollectionAttackTactics Rule #194',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1195',
    name: 'CollectionAttackTactics Rule #195',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1196',
    name: 'CollectionAttackTactics Rule #196',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1197',
    name: 'CollectionAttackTactics Rule #197',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1198',
    name: 'CollectionAttackTactics Rule #198',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1199',
    name: 'CollectionAttackTactics Rule #199',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1200',
    name: 'CollectionAttackTactics Rule #200',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1201',
    name: 'CollectionAttackTactics Rule #201',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1202',
    name: 'CollectionAttackTactics Rule #202',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1203',
    name: 'CollectionAttackTactics Rule #203',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1204',
    name: 'CollectionAttackTactics Rule #204',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1205',
    name: 'CollectionAttackTactics Rule #205',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1206',
    name: 'CollectionAttackTactics Rule #206',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1207',
    name: 'CollectionAttackTactics Rule #207',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1208',
    name: 'CollectionAttackTactics Rule #208',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1209',
    name: 'CollectionAttackTactics Rule #209',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1210',
    name: 'CollectionAttackTactics Rule #210',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1211',
    name: 'CollectionAttackTactics Rule #211',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1212',
    name: 'CollectionAttackTactics Rule #212',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1213',
    name: 'CollectionAttackTactics Rule #213',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1214',
    name: 'CollectionAttackTactics Rule #214',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1215',
    name: 'CollectionAttackTactics Rule #215',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1216',
    name: 'CollectionAttackTactics Rule #216',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1217',
    name: 'CollectionAttackTactics Rule #217',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1218',
    name: 'CollectionAttackTactics Rule #218',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1219',
    name: 'CollectionAttackTactics Rule #219',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1220',
    name: 'CollectionAttackTactics Rule #220',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1221',
    name: 'CollectionAttackTactics Rule #221',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1222',
    name: 'CollectionAttackTactics Rule #222',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1223',
    name: 'CollectionAttackTactics Rule #223',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1224',
    name: 'CollectionAttackTactics Rule #224',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1225',
    name: 'CollectionAttackTactics Rule #225',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1226',
    name: 'CollectionAttackTactics Rule #226',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1227',
    name: 'CollectionAttackTactics Rule #227',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1228',
    name: 'CollectionAttackTactics Rule #228',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1229',
    name: 'CollectionAttackTactics Rule #229',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1230',
    name: 'CollectionAttackTactics Rule #230',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1231',
    name: 'CollectionAttackTactics Rule #231',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1232',
    name: 'CollectionAttackTactics Rule #232',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1233',
    name: 'CollectionAttackTactics Rule #233',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1234',
    name: 'CollectionAttackTactics Rule #234',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1235',
    name: 'CollectionAttackTactics Rule #235',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1236',
    name: 'CollectionAttackTactics Rule #236',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1237',
    name: 'CollectionAttackTactics Rule #237',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1238',
    name: 'CollectionAttackTactics Rule #238',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1239',
    name: 'CollectionAttackTactics Rule #239',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1240',
    name: 'CollectionAttackTactics Rule #240',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1241',
    name: 'CollectionAttackTactics Rule #241',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1242',
    name: 'CollectionAttackTactics Rule #242',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1243',
    name: 'CollectionAttackTactics Rule #243',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1244',
    name: 'CollectionAttackTactics Rule #244',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1245',
    name: 'CollectionAttackTactics Rule #245',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1246',
    name: 'CollectionAttackTactics Rule #246',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1247',
    name: 'CollectionAttackTactics Rule #247',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1248',
    name: 'CollectionAttackTactics Rule #248',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1249',
    name: 'CollectionAttackTactics Rule #249',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1250',
    name: 'CollectionAttackTactics Rule #250',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1251',
    name: 'CollectionAttackTactics Rule #251',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1252',
    name: 'CollectionAttackTactics Rule #252',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1253',
    name: 'CollectionAttackTactics Rule #253',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1254',
    name: 'CollectionAttackTactics Rule #254',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1255',
    name: 'CollectionAttackTactics Rule #255',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1256',
    name: 'CollectionAttackTactics Rule #256',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1257',
    name: 'CollectionAttackTactics Rule #257',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1258',
    name: 'CollectionAttackTactics Rule #258',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1259',
    name: 'CollectionAttackTactics Rule #259',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1260',
    name: 'CollectionAttackTactics Rule #260',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1261',
    name: 'CollectionAttackTactics Rule #261',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1262',
    name: 'CollectionAttackTactics Rule #262',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1263',
    name: 'CollectionAttackTactics Rule #263',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1264',
    name: 'CollectionAttackTactics Rule #264',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1265',
    name: 'CollectionAttackTactics Rule #265',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1266',
    name: 'CollectionAttackTactics Rule #266',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1267',
    name: 'CollectionAttackTactics Rule #267',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1268',
    name: 'CollectionAttackTactics Rule #268',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1269',
    name: 'CollectionAttackTactics Rule #269',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1270',
    name: 'CollectionAttackTactics Rule #270',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1271',
    name: 'CollectionAttackTactics Rule #271',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1272',
    name: 'CollectionAttackTactics Rule #272',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1273',
    name: 'CollectionAttackTactics Rule #273',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1274',
    name: 'CollectionAttackTactics Rule #274',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1275',
    name: 'CollectionAttackTactics Rule #275',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1276',
    name: 'CollectionAttackTactics Rule #276',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1277',
    name: 'CollectionAttackTactics Rule #277',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1278',
    name: 'CollectionAttackTactics Rule #278',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1279',
    name: 'CollectionAttackTactics Rule #279',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1280',
    name: 'CollectionAttackTactics Rule #280',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1281',
    name: 'CollectionAttackTactics Rule #281',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1282',
    name: 'CollectionAttackTactics Rule #282',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1283',
    name: 'CollectionAttackTactics Rule #283',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1284',
    name: 'CollectionAttackTactics Rule #284',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1285',
    name: 'CollectionAttackTactics Rule #285',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1286',
    name: 'CollectionAttackTactics Rule #286',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1287',
    name: 'CollectionAttackTactics Rule #287',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1288',
    name: 'CollectionAttackTactics Rule #288',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1289',
    name: 'CollectionAttackTactics Rule #289',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1290',
    name: 'CollectionAttackTactics Rule #290',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1291',
    name: 'CollectionAttackTactics Rule #291',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1292',
    name: 'CollectionAttackTactics Rule #292',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1293',
    name: 'CollectionAttackTactics Rule #293',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1294',
    name: 'CollectionAttackTactics Rule #294',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1295',
    name: 'CollectionAttackTactics Rule #295',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1296',
    name: 'CollectionAttackTactics Rule #296',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1297',
    name: 'CollectionAttackTactics Rule #297',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1298',
    name: 'CollectionAttackTactics Rule #298',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1299',
    name: 'CollectionAttackTactics Rule #299',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1300',
    name: 'CollectionAttackTactics Rule #300',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1301',
    name: 'CollectionAttackTactics Rule #301',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1302',
    name: 'CollectionAttackTactics Rule #302',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1303',
    name: 'CollectionAttackTactics Rule #303',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1304',
    name: 'CollectionAttackTactics Rule #304',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1305',
    name: 'CollectionAttackTactics Rule #305',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1306',
    name: 'CollectionAttackTactics Rule #306',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1307',
    name: 'CollectionAttackTactics Rule #307',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1308',
    name: 'CollectionAttackTactics Rule #308',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1309',
    name: 'CollectionAttackTactics Rule #309',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1310',
    name: 'CollectionAttackTactics Rule #310',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1311',
    name: 'CollectionAttackTactics Rule #311',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1312',
    name: 'CollectionAttackTactics Rule #312',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1313',
    name: 'CollectionAttackTactics Rule #313',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1314',
    name: 'CollectionAttackTactics Rule #314',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1315',
    name: 'CollectionAttackTactics Rule #315',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1316',
    name: 'CollectionAttackTactics Rule #316',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1317',
    name: 'CollectionAttackTactics Rule #317',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1318',
    name: 'CollectionAttackTactics Rule #318',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1319',
    name: 'CollectionAttackTactics Rule #319',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1320',
    name: 'CollectionAttackTactics Rule #320',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1321',
    name: 'CollectionAttackTactics Rule #321',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1322',
    name: 'CollectionAttackTactics Rule #322',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1323',
    name: 'CollectionAttackTactics Rule #323',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1324',
    name: 'CollectionAttackTactics Rule #324',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1325',
    name: 'CollectionAttackTactics Rule #325',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1326',
    name: 'CollectionAttackTactics Rule #326',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1327',
    name: 'CollectionAttackTactics Rule #327',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1328',
    name: 'CollectionAttackTactics Rule #328',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1329',
    name: 'CollectionAttackTactics Rule #329',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1330',
    name: 'CollectionAttackTactics Rule #330',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1331',
    name: 'CollectionAttackTactics Rule #331',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1332',
    name: 'CollectionAttackTactics Rule #332',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1333',
    name: 'CollectionAttackTactics Rule #333',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1334',
    name: 'CollectionAttackTactics Rule #334',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1335',
    name: 'CollectionAttackTactics Rule #335',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1336',
    name: 'CollectionAttackTactics Rule #336',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1337',
    name: 'CollectionAttackTactics Rule #337',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1338',
    name: 'CollectionAttackTactics Rule #338',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1339',
    name: 'CollectionAttackTactics Rule #339',
    category: 'and email harvesting',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1340',
    name: 'CollectionAttackTactics Rule #340',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1341',
    name: 'CollectionAttackTactics Rule #341',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1342',
    name: 'CollectionAttackTactics Rule #342',
    category: 'screen capture',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1343',
    name: 'CollectionAttackTactics Rule #343',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1344',
    name: 'CollectionAttackTactics Rule #344',
    category: 'Automated data staging',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1345',
    name: 'CollectionAttackTactics Rule #345',
    category: 'clipboard monitoring',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1346',
    name: 'CollectionAttackTactics Rule #346',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1347',
    name: 'CollectionAttackTactics Rule #347',
    category: 'and email harvesting',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1348',
    name: 'CollectionAttackTactics Rule #348',
    category: 'Automated data staging',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1349',
    name: 'CollectionAttackTactics Rule #349',
    category: 'clipboard monitoring',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0009-T1350',
    name: 'CollectionAttackTactics Rule #350',
    category: 'screen capture',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0009_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0009_DATASET.slice(0, 20);
    return MITRE_TA0009_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
