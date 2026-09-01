/**
 * MITRE ATT&CK Enterprise Matrix: ImpactDestructionTactics
 * Threat Scope: Ransomware disk wiping, service disruption DDoS, volume shadow copy deletion, and data destruction
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

export const MITRE_TA0012_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0012-T1001',
    name: 'ImpactDestructionTactics Rule #1',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1002',
    name: 'ImpactDestructionTactics Rule #2',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1003',
    name: 'ImpactDestructionTactics Rule #3',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1004',
    name: 'ImpactDestructionTactics Rule #4',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1005',
    name: 'ImpactDestructionTactics Rule #5',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1006',
    name: 'ImpactDestructionTactics Rule #6',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1007',
    name: 'ImpactDestructionTactics Rule #7',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1008',
    name: 'ImpactDestructionTactics Rule #8',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1009',
    name: 'ImpactDestructionTactics Rule #9',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1010',
    name: 'ImpactDestructionTactics Rule #10',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1011',
    name: 'ImpactDestructionTactics Rule #11',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1012',
    name: 'ImpactDestructionTactics Rule #12',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1013',
    name: 'ImpactDestructionTactics Rule #13',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1014',
    name: 'ImpactDestructionTactics Rule #14',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1015',
    name: 'ImpactDestructionTactics Rule #15',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1016',
    name: 'ImpactDestructionTactics Rule #16',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1017',
    name: 'ImpactDestructionTactics Rule #17',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1018',
    name: 'ImpactDestructionTactics Rule #18',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1019',
    name: 'ImpactDestructionTactics Rule #19',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1020',
    name: 'ImpactDestructionTactics Rule #20',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1021',
    name: 'ImpactDestructionTactics Rule #21',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1022',
    name: 'ImpactDestructionTactics Rule #22',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1023',
    name: 'ImpactDestructionTactics Rule #23',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1024',
    name: 'ImpactDestructionTactics Rule #24',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1025',
    name: 'ImpactDestructionTactics Rule #25',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1026',
    name: 'ImpactDestructionTactics Rule #26',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1027',
    name: 'ImpactDestructionTactics Rule #27',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1028',
    name: 'ImpactDestructionTactics Rule #28',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1029',
    name: 'ImpactDestructionTactics Rule #29',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1030',
    name: 'ImpactDestructionTactics Rule #30',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1031',
    name: 'ImpactDestructionTactics Rule #31',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1032',
    name: 'ImpactDestructionTactics Rule #32',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1033',
    name: 'ImpactDestructionTactics Rule #33',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1034',
    name: 'ImpactDestructionTactics Rule #34',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1035',
    name: 'ImpactDestructionTactics Rule #35',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1036',
    name: 'ImpactDestructionTactics Rule #36',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1037',
    name: 'ImpactDestructionTactics Rule #37',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1038',
    name: 'ImpactDestructionTactics Rule #38',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1039',
    name: 'ImpactDestructionTactics Rule #39',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1040',
    name: 'ImpactDestructionTactics Rule #40',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1041',
    name: 'ImpactDestructionTactics Rule #41',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1042',
    name: 'ImpactDestructionTactics Rule #42',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1043',
    name: 'ImpactDestructionTactics Rule #43',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1044',
    name: 'ImpactDestructionTactics Rule #44',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1045',
    name: 'ImpactDestructionTactics Rule #45',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1046',
    name: 'ImpactDestructionTactics Rule #46',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1047',
    name: 'ImpactDestructionTactics Rule #47',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1048',
    name: 'ImpactDestructionTactics Rule #48',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1049',
    name: 'ImpactDestructionTactics Rule #49',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1050',
    name: 'ImpactDestructionTactics Rule #50',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1051',
    name: 'ImpactDestructionTactics Rule #51',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1052',
    name: 'ImpactDestructionTactics Rule #52',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1053',
    name: 'ImpactDestructionTactics Rule #53',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1054',
    name: 'ImpactDestructionTactics Rule #54',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1055',
    name: 'ImpactDestructionTactics Rule #55',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1056',
    name: 'ImpactDestructionTactics Rule #56',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1057',
    name: 'ImpactDestructionTactics Rule #57',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1058',
    name: 'ImpactDestructionTactics Rule #58',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1059',
    name: 'ImpactDestructionTactics Rule #59',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1060',
    name: 'ImpactDestructionTactics Rule #60',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1061',
    name: 'ImpactDestructionTactics Rule #61',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1062',
    name: 'ImpactDestructionTactics Rule #62',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1063',
    name: 'ImpactDestructionTactics Rule #63',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1064',
    name: 'ImpactDestructionTactics Rule #64',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1065',
    name: 'ImpactDestructionTactics Rule #65',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1066',
    name: 'ImpactDestructionTactics Rule #66',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1067',
    name: 'ImpactDestructionTactics Rule #67',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1068',
    name: 'ImpactDestructionTactics Rule #68',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1069',
    name: 'ImpactDestructionTactics Rule #69',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1070',
    name: 'ImpactDestructionTactics Rule #70',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1071',
    name: 'ImpactDestructionTactics Rule #71',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1072',
    name: 'ImpactDestructionTactics Rule #72',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1073',
    name: 'ImpactDestructionTactics Rule #73',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1074',
    name: 'ImpactDestructionTactics Rule #74',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1075',
    name: 'ImpactDestructionTactics Rule #75',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1076',
    name: 'ImpactDestructionTactics Rule #76',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1077',
    name: 'ImpactDestructionTactics Rule #77',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1078',
    name: 'ImpactDestructionTactics Rule #78',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1079',
    name: 'ImpactDestructionTactics Rule #79',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1080',
    name: 'ImpactDestructionTactics Rule #80',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1081',
    name: 'ImpactDestructionTactics Rule #81',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1082',
    name: 'ImpactDestructionTactics Rule #82',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1083',
    name: 'ImpactDestructionTactics Rule #83',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1084',
    name: 'ImpactDestructionTactics Rule #84',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1085',
    name: 'ImpactDestructionTactics Rule #85',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1086',
    name: 'ImpactDestructionTactics Rule #86',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1087',
    name: 'ImpactDestructionTactics Rule #87',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1088',
    name: 'ImpactDestructionTactics Rule #88',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1089',
    name: 'ImpactDestructionTactics Rule #89',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1090',
    name: 'ImpactDestructionTactics Rule #90',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1091',
    name: 'ImpactDestructionTactics Rule #91',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1092',
    name: 'ImpactDestructionTactics Rule #92',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1093',
    name: 'ImpactDestructionTactics Rule #93',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1094',
    name: 'ImpactDestructionTactics Rule #94',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1095',
    name: 'ImpactDestructionTactics Rule #95',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1096',
    name: 'ImpactDestructionTactics Rule #96',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1097',
    name: 'ImpactDestructionTactics Rule #97',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1098',
    name: 'ImpactDestructionTactics Rule #98',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1099',
    name: 'ImpactDestructionTactics Rule #99',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1100',
    name: 'ImpactDestructionTactics Rule #100',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1101',
    name: 'ImpactDestructionTactics Rule #101',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1102',
    name: 'ImpactDestructionTactics Rule #102',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1103',
    name: 'ImpactDestructionTactics Rule #103',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1104',
    name: 'ImpactDestructionTactics Rule #104',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1105',
    name: 'ImpactDestructionTactics Rule #105',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1106',
    name: 'ImpactDestructionTactics Rule #106',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1107',
    name: 'ImpactDestructionTactics Rule #107',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1108',
    name: 'ImpactDestructionTactics Rule #108',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1109',
    name: 'ImpactDestructionTactics Rule #109',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1110',
    name: 'ImpactDestructionTactics Rule #110',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1111',
    name: 'ImpactDestructionTactics Rule #111',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1112',
    name: 'ImpactDestructionTactics Rule #112',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1113',
    name: 'ImpactDestructionTactics Rule #113',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1114',
    name: 'ImpactDestructionTactics Rule #114',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1115',
    name: 'ImpactDestructionTactics Rule #115',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1116',
    name: 'ImpactDestructionTactics Rule #116',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1117',
    name: 'ImpactDestructionTactics Rule #117',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1118',
    name: 'ImpactDestructionTactics Rule #118',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1119',
    name: 'ImpactDestructionTactics Rule #119',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1120',
    name: 'ImpactDestructionTactics Rule #120',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1121',
    name: 'ImpactDestructionTactics Rule #121',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1122',
    name: 'ImpactDestructionTactics Rule #122',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1123',
    name: 'ImpactDestructionTactics Rule #123',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1124',
    name: 'ImpactDestructionTactics Rule #124',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1125',
    name: 'ImpactDestructionTactics Rule #125',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1126',
    name: 'ImpactDestructionTactics Rule #126',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1127',
    name: 'ImpactDestructionTactics Rule #127',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1128',
    name: 'ImpactDestructionTactics Rule #128',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1129',
    name: 'ImpactDestructionTactics Rule #129',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1130',
    name: 'ImpactDestructionTactics Rule #130',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1131',
    name: 'ImpactDestructionTactics Rule #131',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1132',
    name: 'ImpactDestructionTactics Rule #132',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1133',
    name: 'ImpactDestructionTactics Rule #133',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1134',
    name: 'ImpactDestructionTactics Rule #134',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1135',
    name: 'ImpactDestructionTactics Rule #135',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1136',
    name: 'ImpactDestructionTactics Rule #136',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1137',
    name: 'ImpactDestructionTactics Rule #137',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1138',
    name: 'ImpactDestructionTactics Rule #138',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1139',
    name: 'ImpactDestructionTactics Rule #139',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1140',
    name: 'ImpactDestructionTactics Rule #140',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1141',
    name: 'ImpactDestructionTactics Rule #141',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1142',
    name: 'ImpactDestructionTactics Rule #142',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1143',
    name: 'ImpactDestructionTactics Rule #143',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1144',
    name: 'ImpactDestructionTactics Rule #144',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1145',
    name: 'ImpactDestructionTactics Rule #145',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1146',
    name: 'ImpactDestructionTactics Rule #146',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1147',
    name: 'ImpactDestructionTactics Rule #147',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1148',
    name: 'ImpactDestructionTactics Rule #148',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1149',
    name: 'ImpactDestructionTactics Rule #149',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1150',
    name: 'ImpactDestructionTactics Rule #150',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1151',
    name: 'ImpactDestructionTactics Rule #151',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1152',
    name: 'ImpactDestructionTactics Rule #152',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1153',
    name: 'ImpactDestructionTactics Rule #153',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1154',
    name: 'ImpactDestructionTactics Rule #154',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1155',
    name: 'ImpactDestructionTactics Rule #155',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1156',
    name: 'ImpactDestructionTactics Rule #156',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1157',
    name: 'ImpactDestructionTactics Rule #157',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1158',
    name: 'ImpactDestructionTactics Rule #158',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1159',
    name: 'ImpactDestructionTactics Rule #159',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1160',
    name: 'ImpactDestructionTactics Rule #160',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1161',
    name: 'ImpactDestructionTactics Rule #161',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1162',
    name: 'ImpactDestructionTactics Rule #162',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1163',
    name: 'ImpactDestructionTactics Rule #163',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1164',
    name: 'ImpactDestructionTactics Rule #164',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1165',
    name: 'ImpactDestructionTactics Rule #165',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1166',
    name: 'ImpactDestructionTactics Rule #166',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1167',
    name: 'ImpactDestructionTactics Rule #167',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1168',
    name: 'ImpactDestructionTactics Rule #168',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1169',
    name: 'ImpactDestructionTactics Rule #169',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1170',
    name: 'ImpactDestructionTactics Rule #170',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1171',
    name: 'ImpactDestructionTactics Rule #171',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1172',
    name: 'ImpactDestructionTactics Rule #172',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1173',
    name: 'ImpactDestructionTactics Rule #173',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1174',
    name: 'ImpactDestructionTactics Rule #174',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1175',
    name: 'ImpactDestructionTactics Rule #175',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1176',
    name: 'ImpactDestructionTactics Rule #176',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1177',
    name: 'ImpactDestructionTactics Rule #177',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1178',
    name: 'ImpactDestructionTactics Rule #178',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1179',
    name: 'ImpactDestructionTactics Rule #179',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1180',
    name: 'ImpactDestructionTactics Rule #180',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1181',
    name: 'ImpactDestructionTactics Rule #181',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1182',
    name: 'ImpactDestructionTactics Rule #182',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1183',
    name: 'ImpactDestructionTactics Rule #183',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1184',
    name: 'ImpactDestructionTactics Rule #184',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1185',
    name: 'ImpactDestructionTactics Rule #185',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1186',
    name: 'ImpactDestructionTactics Rule #186',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1187',
    name: 'ImpactDestructionTactics Rule #187',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1188',
    name: 'ImpactDestructionTactics Rule #188',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1189',
    name: 'ImpactDestructionTactics Rule #189',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1190',
    name: 'ImpactDestructionTactics Rule #190',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1191',
    name: 'ImpactDestructionTactics Rule #191',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1192',
    name: 'ImpactDestructionTactics Rule #192',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1193',
    name: 'ImpactDestructionTactics Rule #193',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1194',
    name: 'ImpactDestructionTactics Rule #194',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1195',
    name: 'ImpactDestructionTactics Rule #195',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1196',
    name: 'ImpactDestructionTactics Rule #196',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1197',
    name: 'ImpactDestructionTactics Rule #197',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1198',
    name: 'ImpactDestructionTactics Rule #198',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1199',
    name: 'ImpactDestructionTactics Rule #199',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1200',
    name: 'ImpactDestructionTactics Rule #200',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1201',
    name: 'ImpactDestructionTactics Rule #201',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1202',
    name: 'ImpactDestructionTactics Rule #202',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1203',
    name: 'ImpactDestructionTactics Rule #203',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1204',
    name: 'ImpactDestructionTactics Rule #204',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1205',
    name: 'ImpactDestructionTactics Rule #205',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1206',
    name: 'ImpactDestructionTactics Rule #206',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1207',
    name: 'ImpactDestructionTactics Rule #207',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1208',
    name: 'ImpactDestructionTactics Rule #208',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1209',
    name: 'ImpactDestructionTactics Rule #209',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1210',
    name: 'ImpactDestructionTactics Rule #210',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1211',
    name: 'ImpactDestructionTactics Rule #211',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1212',
    name: 'ImpactDestructionTactics Rule #212',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1213',
    name: 'ImpactDestructionTactics Rule #213',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1214',
    name: 'ImpactDestructionTactics Rule #214',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1215',
    name: 'ImpactDestructionTactics Rule #215',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1216',
    name: 'ImpactDestructionTactics Rule #216',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1217',
    name: 'ImpactDestructionTactics Rule #217',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1218',
    name: 'ImpactDestructionTactics Rule #218',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1219',
    name: 'ImpactDestructionTactics Rule #219',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1220',
    name: 'ImpactDestructionTactics Rule #220',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1221',
    name: 'ImpactDestructionTactics Rule #221',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1222',
    name: 'ImpactDestructionTactics Rule #222',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1223',
    name: 'ImpactDestructionTactics Rule #223',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1224',
    name: 'ImpactDestructionTactics Rule #224',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1225',
    name: 'ImpactDestructionTactics Rule #225',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1226',
    name: 'ImpactDestructionTactics Rule #226',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1227',
    name: 'ImpactDestructionTactics Rule #227',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1228',
    name: 'ImpactDestructionTactics Rule #228',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1229',
    name: 'ImpactDestructionTactics Rule #229',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1230',
    name: 'ImpactDestructionTactics Rule #230',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1231',
    name: 'ImpactDestructionTactics Rule #231',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1232',
    name: 'ImpactDestructionTactics Rule #232',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1233',
    name: 'ImpactDestructionTactics Rule #233',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1234',
    name: 'ImpactDestructionTactics Rule #234',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1235',
    name: 'ImpactDestructionTactics Rule #235',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1236',
    name: 'ImpactDestructionTactics Rule #236',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1237',
    name: 'ImpactDestructionTactics Rule #237',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1238',
    name: 'ImpactDestructionTactics Rule #238',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1239',
    name: 'ImpactDestructionTactics Rule #239',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1240',
    name: 'ImpactDestructionTactics Rule #240',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1241',
    name: 'ImpactDestructionTactics Rule #241',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1242',
    name: 'ImpactDestructionTactics Rule #242',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1243',
    name: 'ImpactDestructionTactics Rule #243',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1244',
    name: 'ImpactDestructionTactics Rule #244',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1245',
    name: 'ImpactDestructionTactics Rule #245',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1246',
    name: 'ImpactDestructionTactics Rule #246',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1247',
    name: 'ImpactDestructionTactics Rule #247',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1248',
    name: 'ImpactDestructionTactics Rule #248',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1249',
    name: 'ImpactDestructionTactics Rule #249',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1250',
    name: 'ImpactDestructionTactics Rule #250',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1251',
    name: 'ImpactDestructionTactics Rule #251',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1252',
    name: 'ImpactDestructionTactics Rule #252',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1253',
    name: 'ImpactDestructionTactics Rule #253',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1254',
    name: 'ImpactDestructionTactics Rule #254',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1255',
    name: 'ImpactDestructionTactics Rule #255',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1256',
    name: 'ImpactDestructionTactics Rule #256',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1257',
    name: 'ImpactDestructionTactics Rule #257',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1258',
    name: 'ImpactDestructionTactics Rule #258',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1259',
    name: 'ImpactDestructionTactics Rule #259',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1260',
    name: 'ImpactDestructionTactics Rule #260',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1261',
    name: 'ImpactDestructionTactics Rule #261',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1262',
    name: 'ImpactDestructionTactics Rule #262',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1263',
    name: 'ImpactDestructionTactics Rule #263',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1264',
    name: 'ImpactDestructionTactics Rule #264',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1265',
    name: 'ImpactDestructionTactics Rule #265',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1266',
    name: 'ImpactDestructionTactics Rule #266',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1267',
    name: 'ImpactDestructionTactics Rule #267',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1268',
    name: 'ImpactDestructionTactics Rule #268',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1269',
    name: 'ImpactDestructionTactics Rule #269',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1270',
    name: 'ImpactDestructionTactics Rule #270',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1271',
    name: 'ImpactDestructionTactics Rule #271',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1272',
    name: 'ImpactDestructionTactics Rule #272',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1273',
    name: 'ImpactDestructionTactics Rule #273',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1274',
    name: 'ImpactDestructionTactics Rule #274',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1275',
    name: 'ImpactDestructionTactics Rule #275',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1276',
    name: 'ImpactDestructionTactics Rule #276',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1277',
    name: 'ImpactDestructionTactics Rule #277',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1278',
    name: 'ImpactDestructionTactics Rule #278',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1279',
    name: 'ImpactDestructionTactics Rule #279',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1280',
    name: 'ImpactDestructionTactics Rule #280',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1281',
    name: 'ImpactDestructionTactics Rule #281',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1282',
    name: 'ImpactDestructionTactics Rule #282',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1283',
    name: 'ImpactDestructionTactics Rule #283',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1284',
    name: 'ImpactDestructionTactics Rule #284',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1285',
    name: 'ImpactDestructionTactics Rule #285',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1286',
    name: 'ImpactDestructionTactics Rule #286',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1287',
    name: 'ImpactDestructionTactics Rule #287',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1288',
    name: 'ImpactDestructionTactics Rule #288',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1289',
    name: 'ImpactDestructionTactics Rule #289',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1290',
    name: 'ImpactDestructionTactics Rule #290',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1291',
    name: 'ImpactDestructionTactics Rule #291',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1292',
    name: 'ImpactDestructionTactics Rule #292',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1293',
    name: 'ImpactDestructionTactics Rule #293',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1294',
    name: 'ImpactDestructionTactics Rule #294',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1295',
    name: 'ImpactDestructionTactics Rule #295',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1296',
    name: 'ImpactDestructionTactics Rule #296',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1297',
    name: 'ImpactDestructionTactics Rule #297',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1298',
    name: 'ImpactDestructionTactics Rule #298',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1299',
    name: 'ImpactDestructionTactics Rule #299',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1300',
    name: 'ImpactDestructionTactics Rule #300',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1301',
    name: 'ImpactDestructionTactics Rule #301',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1302',
    name: 'ImpactDestructionTactics Rule #302',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1303',
    name: 'ImpactDestructionTactics Rule #303',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1304',
    name: 'ImpactDestructionTactics Rule #304',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1305',
    name: 'ImpactDestructionTactics Rule #305',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1306',
    name: 'ImpactDestructionTactics Rule #306',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1307',
    name: 'ImpactDestructionTactics Rule #307',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1308',
    name: 'ImpactDestructionTactics Rule #308',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1309',
    name: 'ImpactDestructionTactics Rule #309',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1310',
    name: 'ImpactDestructionTactics Rule #310',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1311',
    name: 'ImpactDestructionTactics Rule #311',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1312',
    name: 'ImpactDestructionTactics Rule #312',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1313',
    name: 'ImpactDestructionTactics Rule #313',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1314',
    name: 'ImpactDestructionTactics Rule #314',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1315',
    name: 'ImpactDestructionTactics Rule #315',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1316',
    name: 'ImpactDestructionTactics Rule #316',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1317',
    name: 'ImpactDestructionTactics Rule #317',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1318',
    name: 'ImpactDestructionTactics Rule #318',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1319',
    name: 'ImpactDestructionTactics Rule #319',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1320',
    name: 'ImpactDestructionTactics Rule #320',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1321',
    name: 'ImpactDestructionTactics Rule #321',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1322',
    name: 'ImpactDestructionTactics Rule #322',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1323',
    name: 'ImpactDestructionTactics Rule #323',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1324',
    name: 'ImpactDestructionTactics Rule #324',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1325',
    name: 'ImpactDestructionTactics Rule #325',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1326',
    name: 'ImpactDestructionTactics Rule #326',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1327',
    name: 'ImpactDestructionTactics Rule #327',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1328',
    name: 'ImpactDestructionTactics Rule #328',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1329',
    name: 'ImpactDestructionTactics Rule #329',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1330',
    name: 'ImpactDestructionTactics Rule #330',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1331',
    name: 'ImpactDestructionTactics Rule #331',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1332',
    name: 'ImpactDestructionTactics Rule #332',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1333',
    name: 'ImpactDestructionTactics Rule #333',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1334',
    name: 'ImpactDestructionTactics Rule #334',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1335',
    name: 'ImpactDestructionTactics Rule #335',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1336',
    name: 'ImpactDestructionTactics Rule #336',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1337',
    name: 'ImpactDestructionTactics Rule #337',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1338',
    name: 'ImpactDestructionTactics Rule #338',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1339',
    name: 'ImpactDestructionTactics Rule #339',
    category: 'and data destruction',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1340',
    name: 'ImpactDestructionTactics Rule #340',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1341',
    name: 'ImpactDestructionTactics Rule #341',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1342',
    name: 'ImpactDestructionTactics Rule #342',
    category: 'volume shadow copy deletion',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1343',
    name: 'ImpactDestructionTactics Rule #343',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1344',
    name: 'ImpactDestructionTactics Rule #344',
    category: 'Ransomware disk wiping',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1345',
    name: 'ImpactDestructionTactics Rule #345',
    category: 'service disruption DDoS',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1346',
    name: 'ImpactDestructionTactics Rule #346',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1347',
    name: 'ImpactDestructionTactics Rule #347',
    category: 'and data destruction',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1348',
    name: 'ImpactDestructionTactics Rule #348',
    category: 'Ransomware disk wiping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1349',
    name: 'ImpactDestructionTactics Rule #349',
    category: 'service disruption DDoS',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0012-T1350',
    name: 'ImpactDestructionTactics Rule #350',
    category: 'volume shadow copy deletion',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0012_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0012_DATASET.slice(0, 20);
    return MITRE_TA0012_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
