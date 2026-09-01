/**
 * MITRE ATT&CK Enterprise Matrix: ExfiltrationAttackTactics
 * Threat Scope: Exfiltration over cloud storage, encrypted archive uploads, ICMP tunneling, and scheduled egress
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

export const MITRE_TA0011_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0011-T1001',
    name: 'ExfiltrationAttackTactics Rule #1',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1002',
    name: 'ExfiltrationAttackTactics Rule #2',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1003',
    name: 'ExfiltrationAttackTactics Rule #3',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1004',
    name: 'ExfiltrationAttackTactics Rule #4',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1005',
    name: 'ExfiltrationAttackTactics Rule #5',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1006',
    name: 'ExfiltrationAttackTactics Rule #6',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1007',
    name: 'ExfiltrationAttackTactics Rule #7',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1008',
    name: 'ExfiltrationAttackTactics Rule #8',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1009',
    name: 'ExfiltrationAttackTactics Rule #9',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1010',
    name: 'ExfiltrationAttackTactics Rule #10',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1011',
    name: 'ExfiltrationAttackTactics Rule #11',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1012',
    name: 'ExfiltrationAttackTactics Rule #12',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1013',
    name: 'ExfiltrationAttackTactics Rule #13',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1014',
    name: 'ExfiltrationAttackTactics Rule #14',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1015',
    name: 'ExfiltrationAttackTactics Rule #15',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1016',
    name: 'ExfiltrationAttackTactics Rule #16',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1017',
    name: 'ExfiltrationAttackTactics Rule #17',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1018',
    name: 'ExfiltrationAttackTactics Rule #18',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1019',
    name: 'ExfiltrationAttackTactics Rule #19',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1020',
    name: 'ExfiltrationAttackTactics Rule #20',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1021',
    name: 'ExfiltrationAttackTactics Rule #21',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1022',
    name: 'ExfiltrationAttackTactics Rule #22',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1023',
    name: 'ExfiltrationAttackTactics Rule #23',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1024',
    name: 'ExfiltrationAttackTactics Rule #24',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1025',
    name: 'ExfiltrationAttackTactics Rule #25',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1026',
    name: 'ExfiltrationAttackTactics Rule #26',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1027',
    name: 'ExfiltrationAttackTactics Rule #27',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1028',
    name: 'ExfiltrationAttackTactics Rule #28',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1029',
    name: 'ExfiltrationAttackTactics Rule #29',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1030',
    name: 'ExfiltrationAttackTactics Rule #30',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1031',
    name: 'ExfiltrationAttackTactics Rule #31',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1032',
    name: 'ExfiltrationAttackTactics Rule #32',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1033',
    name: 'ExfiltrationAttackTactics Rule #33',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1034',
    name: 'ExfiltrationAttackTactics Rule #34',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1035',
    name: 'ExfiltrationAttackTactics Rule #35',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1036',
    name: 'ExfiltrationAttackTactics Rule #36',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1037',
    name: 'ExfiltrationAttackTactics Rule #37',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1038',
    name: 'ExfiltrationAttackTactics Rule #38',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1039',
    name: 'ExfiltrationAttackTactics Rule #39',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1040',
    name: 'ExfiltrationAttackTactics Rule #40',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1041',
    name: 'ExfiltrationAttackTactics Rule #41',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1042',
    name: 'ExfiltrationAttackTactics Rule #42',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1043',
    name: 'ExfiltrationAttackTactics Rule #43',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1044',
    name: 'ExfiltrationAttackTactics Rule #44',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1045',
    name: 'ExfiltrationAttackTactics Rule #45',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1046',
    name: 'ExfiltrationAttackTactics Rule #46',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1047',
    name: 'ExfiltrationAttackTactics Rule #47',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1048',
    name: 'ExfiltrationAttackTactics Rule #48',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1049',
    name: 'ExfiltrationAttackTactics Rule #49',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1050',
    name: 'ExfiltrationAttackTactics Rule #50',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1051',
    name: 'ExfiltrationAttackTactics Rule #51',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1052',
    name: 'ExfiltrationAttackTactics Rule #52',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1053',
    name: 'ExfiltrationAttackTactics Rule #53',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1054',
    name: 'ExfiltrationAttackTactics Rule #54',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1055',
    name: 'ExfiltrationAttackTactics Rule #55',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1056',
    name: 'ExfiltrationAttackTactics Rule #56',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1057',
    name: 'ExfiltrationAttackTactics Rule #57',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1058',
    name: 'ExfiltrationAttackTactics Rule #58',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1059',
    name: 'ExfiltrationAttackTactics Rule #59',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1060',
    name: 'ExfiltrationAttackTactics Rule #60',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1061',
    name: 'ExfiltrationAttackTactics Rule #61',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1062',
    name: 'ExfiltrationAttackTactics Rule #62',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1063',
    name: 'ExfiltrationAttackTactics Rule #63',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1064',
    name: 'ExfiltrationAttackTactics Rule #64',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1065',
    name: 'ExfiltrationAttackTactics Rule #65',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1066',
    name: 'ExfiltrationAttackTactics Rule #66',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1067',
    name: 'ExfiltrationAttackTactics Rule #67',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1068',
    name: 'ExfiltrationAttackTactics Rule #68',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1069',
    name: 'ExfiltrationAttackTactics Rule #69',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1070',
    name: 'ExfiltrationAttackTactics Rule #70',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1071',
    name: 'ExfiltrationAttackTactics Rule #71',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1072',
    name: 'ExfiltrationAttackTactics Rule #72',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1073',
    name: 'ExfiltrationAttackTactics Rule #73',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1074',
    name: 'ExfiltrationAttackTactics Rule #74',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1075',
    name: 'ExfiltrationAttackTactics Rule #75',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1076',
    name: 'ExfiltrationAttackTactics Rule #76',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1077',
    name: 'ExfiltrationAttackTactics Rule #77',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1078',
    name: 'ExfiltrationAttackTactics Rule #78',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1079',
    name: 'ExfiltrationAttackTactics Rule #79',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1080',
    name: 'ExfiltrationAttackTactics Rule #80',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1081',
    name: 'ExfiltrationAttackTactics Rule #81',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1082',
    name: 'ExfiltrationAttackTactics Rule #82',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1083',
    name: 'ExfiltrationAttackTactics Rule #83',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1084',
    name: 'ExfiltrationAttackTactics Rule #84',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1085',
    name: 'ExfiltrationAttackTactics Rule #85',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1086',
    name: 'ExfiltrationAttackTactics Rule #86',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1087',
    name: 'ExfiltrationAttackTactics Rule #87',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1088',
    name: 'ExfiltrationAttackTactics Rule #88',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1089',
    name: 'ExfiltrationAttackTactics Rule #89',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1090',
    name: 'ExfiltrationAttackTactics Rule #90',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1091',
    name: 'ExfiltrationAttackTactics Rule #91',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1092',
    name: 'ExfiltrationAttackTactics Rule #92',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1093',
    name: 'ExfiltrationAttackTactics Rule #93',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1094',
    name: 'ExfiltrationAttackTactics Rule #94',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1095',
    name: 'ExfiltrationAttackTactics Rule #95',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1096',
    name: 'ExfiltrationAttackTactics Rule #96',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1097',
    name: 'ExfiltrationAttackTactics Rule #97',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1098',
    name: 'ExfiltrationAttackTactics Rule #98',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1099',
    name: 'ExfiltrationAttackTactics Rule #99',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1100',
    name: 'ExfiltrationAttackTactics Rule #100',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1101',
    name: 'ExfiltrationAttackTactics Rule #101',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1102',
    name: 'ExfiltrationAttackTactics Rule #102',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1103',
    name: 'ExfiltrationAttackTactics Rule #103',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1104',
    name: 'ExfiltrationAttackTactics Rule #104',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1105',
    name: 'ExfiltrationAttackTactics Rule #105',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1106',
    name: 'ExfiltrationAttackTactics Rule #106',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1107',
    name: 'ExfiltrationAttackTactics Rule #107',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1108',
    name: 'ExfiltrationAttackTactics Rule #108',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1109',
    name: 'ExfiltrationAttackTactics Rule #109',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1110',
    name: 'ExfiltrationAttackTactics Rule #110',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1111',
    name: 'ExfiltrationAttackTactics Rule #111',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1112',
    name: 'ExfiltrationAttackTactics Rule #112',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1113',
    name: 'ExfiltrationAttackTactics Rule #113',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1114',
    name: 'ExfiltrationAttackTactics Rule #114',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1115',
    name: 'ExfiltrationAttackTactics Rule #115',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1116',
    name: 'ExfiltrationAttackTactics Rule #116',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1117',
    name: 'ExfiltrationAttackTactics Rule #117',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1118',
    name: 'ExfiltrationAttackTactics Rule #118',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1119',
    name: 'ExfiltrationAttackTactics Rule #119',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1120',
    name: 'ExfiltrationAttackTactics Rule #120',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1121',
    name: 'ExfiltrationAttackTactics Rule #121',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1122',
    name: 'ExfiltrationAttackTactics Rule #122',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1123',
    name: 'ExfiltrationAttackTactics Rule #123',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1124',
    name: 'ExfiltrationAttackTactics Rule #124',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1125',
    name: 'ExfiltrationAttackTactics Rule #125',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1126',
    name: 'ExfiltrationAttackTactics Rule #126',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1127',
    name: 'ExfiltrationAttackTactics Rule #127',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1128',
    name: 'ExfiltrationAttackTactics Rule #128',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1129',
    name: 'ExfiltrationAttackTactics Rule #129',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1130',
    name: 'ExfiltrationAttackTactics Rule #130',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1131',
    name: 'ExfiltrationAttackTactics Rule #131',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1132',
    name: 'ExfiltrationAttackTactics Rule #132',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1133',
    name: 'ExfiltrationAttackTactics Rule #133',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1134',
    name: 'ExfiltrationAttackTactics Rule #134',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1135',
    name: 'ExfiltrationAttackTactics Rule #135',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1136',
    name: 'ExfiltrationAttackTactics Rule #136',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1137',
    name: 'ExfiltrationAttackTactics Rule #137',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1138',
    name: 'ExfiltrationAttackTactics Rule #138',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1139',
    name: 'ExfiltrationAttackTactics Rule #139',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1140',
    name: 'ExfiltrationAttackTactics Rule #140',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1141',
    name: 'ExfiltrationAttackTactics Rule #141',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1142',
    name: 'ExfiltrationAttackTactics Rule #142',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1143',
    name: 'ExfiltrationAttackTactics Rule #143',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1144',
    name: 'ExfiltrationAttackTactics Rule #144',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1145',
    name: 'ExfiltrationAttackTactics Rule #145',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1146',
    name: 'ExfiltrationAttackTactics Rule #146',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1147',
    name: 'ExfiltrationAttackTactics Rule #147',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1148',
    name: 'ExfiltrationAttackTactics Rule #148',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1149',
    name: 'ExfiltrationAttackTactics Rule #149',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1150',
    name: 'ExfiltrationAttackTactics Rule #150',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1151',
    name: 'ExfiltrationAttackTactics Rule #151',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1152',
    name: 'ExfiltrationAttackTactics Rule #152',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1153',
    name: 'ExfiltrationAttackTactics Rule #153',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1154',
    name: 'ExfiltrationAttackTactics Rule #154',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1155',
    name: 'ExfiltrationAttackTactics Rule #155',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1156',
    name: 'ExfiltrationAttackTactics Rule #156',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1157',
    name: 'ExfiltrationAttackTactics Rule #157',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1158',
    name: 'ExfiltrationAttackTactics Rule #158',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1159',
    name: 'ExfiltrationAttackTactics Rule #159',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1160',
    name: 'ExfiltrationAttackTactics Rule #160',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1161',
    name: 'ExfiltrationAttackTactics Rule #161',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1162',
    name: 'ExfiltrationAttackTactics Rule #162',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1163',
    name: 'ExfiltrationAttackTactics Rule #163',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1164',
    name: 'ExfiltrationAttackTactics Rule #164',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1165',
    name: 'ExfiltrationAttackTactics Rule #165',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1166',
    name: 'ExfiltrationAttackTactics Rule #166',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1167',
    name: 'ExfiltrationAttackTactics Rule #167',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1168',
    name: 'ExfiltrationAttackTactics Rule #168',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1169',
    name: 'ExfiltrationAttackTactics Rule #169',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1170',
    name: 'ExfiltrationAttackTactics Rule #170',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1171',
    name: 'ExfiltrationAttackTactics Rule #171',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1172',
    name: 'ExfiltrationAttackTactics Rule #172',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1173',
    name: 'ExfiltrationAttackTactics Rule #173',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1174',
    name: 'ExfiltrationAttackTactics Rule #174',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1175',
    name: 'ExfiltrationAttackTactics Rule #175',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1176',
    name: 'ExfiltrationAttackTactics Rule #176',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1177',
    name: 'ExfiltrationAttackTactics Rule #177',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1178',
    name: 'ExfiltrationAttackTactics Rule #178',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1179',
    name: 'ExfiltrationAttackTactics Rule #179',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1180',
    name: 'ExfiltrationAttackTactics Rule #180',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1181',
    name: 'ExfiltrationAttackTactics Rule #181',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1182',
    name: 'ExfiltrationAttackTactics Rule #182',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1183',
    name: 'ExfiltrationAttackTactics Rule #183',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1184',
    name: 'ExfiltrationAttackTactics Rule #184',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1185',
    name: 'ExfiltrationAttackTactics Rule #185',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1186',
    name: 'ExfiltrationAttackTactics Rule #186',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1187',
    name: 'ExfiltrationAttackTactics Rule #187',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1188',
    name: 'ExfiltrationAttackTactics Rule #188',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1189',
    name: 'ExfiltrationAttackTactics Rule #189',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1190',
    name: 'ExfiltrationAttackTactics Rule #190',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1191',
    name: 'ExfiltrationAttackTactics Rule #191',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1192',
    name: 'ExfiltrationAttackTactics Rule #192',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1193',
    name: 'ExfiltrationAttackTactics Rule #193',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1194',
    name: 'ExfiltrationAttackTactics Rule #194',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1195',
    name: 'ExfiltrationAttackTactics Rule #195',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1196',
    name: 'ExfiltrationAttackTactics Rule #196',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1197',
    name: 'ExfiltrationAttackTactics Rule #197',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1198',
    name: 'ExfiltrationAttackTactics Rule #198',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1199',
    name: 'ExfiltrationAttackTactics Rule #199',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1200',
    name: 'ExfiltrationAttackTactics Rule #200',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1201',
    name: 'ExfiltrationAttackTactics Rule #201',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1202',
    name: 'ExfiltrationAttackTactics Rule #202',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1203',
    name: 'ExfiltrationAttackTactics Rule #203',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1204',
    name: 'ExfiltrationAttackTactics Rule #204',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1205',
    name: 'ExfiltrationAttackTactics Rule #205',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1206',
    name: 'ExfiltrationAttackTactics Rule #206',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1207',
    name: 'ExfiltrationAttackTactics Rule #207',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1208',
    name: 'ExfiltrationAttackTactics Rule #208',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1209',
    name: 'ExfiltrationAttackTactics Rule #209',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1210',
    name: 'ExfiltrationAttackTactics Rule #210',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1211',
    name: 'ExfiltrationAttackTactics Rule #211',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1212',
    name: 'ExfiltrationAttackTactics Rule #212',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1213',
    name: 'ExfiltrationAttackTactics Rule #213',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1214',
    name: 'ExfiltrationAttackTactics Rule #214',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1215',
    name: 'ExfiltrationAttackTactics Rule #215',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1216',
    name: 'ExfiltrationAttackTactics Rule #216',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1217',
    name: 'ExfiltrationAttackTactics Rule #217',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1218',
    name: 'ExfiltrationAttackTactics Rule #218',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1219',
    name: 'ExfiltrationAttackTactics Rule #219',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1220',
    name: 'ExfiltrationAttackTactics Rule #220',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1221',
    name: 'ExfiltrationAttackTactics Rule #221',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1222',
    name: 'ExfiltrationAttackTactics Rule #222',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1223',
    name: 'ExfiltrationAttackTactics Rule #223',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1224',
    name: 'ExfiltrationAttackTactics Rule #224',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1225',
    name: 'ExfiltrationAttackTactics Rule #225',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1226',
    name: 'ExfiltrationAttackTactics Rule #226',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1227',
    name: 'ExfiltrationAttackTactics Rule #227',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1228',
    name: 'ExfiltrationAttackTactics Rule #228',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1229',
    name: 'ExfiltrationAttackTactics Rule #229',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1230',
    name: 'ExfiltrationAttackTactics Rule #230',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1231',
    name: 'ExfiltrationAttackTactics Rule #231',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1232',
    name: 'ExfiltrationAttackTactics Rule #232',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1233',
    name: 'ExfiltrationAttackTactics Rule #233',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1234',
    name: 'ExfiltrationAttackTactics Rule #234',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1235',
    name: 'ExfiltrationAttackTactics Rule #235',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1236',
    name: 'ExfiltrationAttackTactics Rule #236',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1237',
    name: 'ExfiltrationAttackTactics Rule #237',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1238',
    name: 'ExfiltrationAttackTactics Rule #238',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1239',
    name: 'ExfiltrationAttackTactics Rule #239',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1240',
    name: 'ExfiltrationAttackTactics Rule #240',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1241',
    name: 'ExfiltrationAttackTactics Rule #241',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1242',
    name: 'ExfiltrationAttackTactics Rule #242',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1243',
    name: 'ExfiltrationAttackTactics Rule #243',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1244',
    name: 'ExfiltrationAttackTactics Rule #244',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1245',
    name: 'ExfiltrationAttackTactics Rule #245',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1246',
    name: 'ExfiltrationAttackTactics Rule #246',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1247',
    name: 'ExfiltrationAttackTactics Rule #247',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1248',
    name: 'ExfiltrationAttackTactics Rule #248',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1249',
    name: 'ExfiltrationAttackTactics Rule #249',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1250',
    name: 'ExfiltrationAttackTactics Rule #250',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1251',
    name: 'ExfiltrationAttackTactics Rule #251',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1252',
    name: 'ExfiltrationAttackTactics Rule #252',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1253',
    name: 'ExfiltrationAttackTactics Rule #253',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1254',
    name: 'ExfiltrationAttackTactics Rule #254',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1255',
    name: 'ExfiltrationAttackTactics Rule #255',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1256',
    name: 'ExfiltrationAttackTactics Rule #256',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1257',
    name: 'ExfiltrationAttackTactics Rule #257',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1258',
    name: 'ExfiltrationAttackTactics Rule #258',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1259',
    name: 'ExfiltrationAttackTactics Rule #259',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1260',
    name: 'ExfiltrationAttackTactics Rule #260',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1261',
    name: 'ExfiltrationAttackTactics Rule #261',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1262',
    name: 'ExfiltrationAttackTactics Rule #262',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1263',
    name: 'ExfiltrationAttackTactics Rule #263',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1264',
    name: 'ExfiltrationAttackTactics Rule #264',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1265',
    name: 'ExfiltrationAttackTactics Rule #265',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1266',
    name: 'ExfiltrationAttackTactics Rule #266',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1267',
    name: 'ExfiltrationAttackTactics Rule #267',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1268',
    name: 'ExfiltrationAttackTactics Rule #268',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1269',
    name: 'ExfiltrationAttackTactics Rule #269',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1270',
    name: 'ExfiltrationAttackTactics Rule #270',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1271',
    name: 'ExfiltrationAttackTactics Rule #271',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1272',
    name: 'ExfiltrationAttackTactics Rule #272',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1273',
    name: 'ExfiltrationAttackTactics Rule #273',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1274',
    name: 'ExfiltrationAttackTactics Rule #274',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1275',
    name: 'ExfiltrationAttackTactics Rule #275',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1276',
    name: 'ExfiltrationAttackTactics Rule #276',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1277',
    name: 'ExfiltrationAttackTactics Rule #277',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1278',
    name: 'ExfiltrationAttackTactics Rule #278',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1279',
    name: 'ExfiltrationAttackTactics Rule #279',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1280',
    name: 'ExfiltrationAttackTactics Rule #280',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1281',
    name: 'ExfiltrationAttackTactics Rule #281',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1282',
    name: 'ExfiltrationAttackTactics Rule #282',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1283',
    name: 'ExfiltrationAttackTactics Rule #283',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1284',
    name: 'ExfiltrationAttackTactics Rule #284',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1285',
    name: 'ExfiltrationAttackTactics Rule #285',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1286',
    name: 'ExfiltrationAttackTactics Rule #286',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1287',
    name: 'ExfiltrationAttackTactics Rule #287',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1288',
    name: 'ExfiltrationAttackTactics Rule #288',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1289',
    name: 'ExfiltrationAttackTactics Rule #289',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1290',
    name: 'ExfiltrationAttackTactics Rule #290',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1291',
    name: 'ExfiltrationAttackTactics Rule #291',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1292',
    name: 'ExfiltrationAttackTactics Rule #292',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1293',
    name: 'ExfiltrationAttackTactics Rule #293',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1294',
    name: 'ExfiltrationAttackTactics Rule #294',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1295',
    name: 'ExfiltrationAttackTactics Rule #295',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1296',
    name: 'ExfiltrationAttackTactics Rule #296',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1297',
    name: 'ExfiltrationAttackTactics Rule #297',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1298',
    name: 'ExfiltrationAttackTactics Rule #298',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1299',
    name: 'ExfiltrationAttackTactics Rule #299',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1300',
    name: 'ExfiltrationAttackTactics Rule #300',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1301',
    name: 'ExfiltrationAttackTactics Rule #301',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1302',
    name: 'ExfiltrationAttackTactics Rule #302',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1303',
    name: 'ExfiltrationAttackTactics Rule #303',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1304',
    name: 'ExfiltrationAttackTactics Rule #304',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1305',
    name: 'ExfiltrationAttackTactics Rule #305',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1306',
    name: 'ExfiltrationAttackTactics Rule #306',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1307',
    name: 'ExfiltrationAttackTactics Rule #307',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1308',
    name: 'ExfiltrationAttackTactics Rule #308',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1309',
    name: 'ExfiltrationAttackTactics Rule #309',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1310',
    name: 'ExfiltrationAttackTactics Rule #310',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1311',
    name: 'ExfiltrationAttackTactics Rule #311',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1312',
    name: 'ExfiltrationAttackTactics Rule #312',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1313',
    name: 'ExfiltrationAttackTactics Rule #313',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1314',
    name: 'ExfiltrationAttackTactics Rule #314',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1315',
    name: 'ExfiltrationAttackTactics Rule #315',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1316',
    name: 'ExfiltrationAttackTactics Rule #316',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1317',
    name: 'ExfiltrationAttackTactics Rule #317',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1318',
    name: 'ExfiltrationAttackTactics Rule #318',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1319',
    name: 'ExfiltrationAttackTactics Rule #319',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1320',
    name: 'ExfiltrationAttackTactics Rule #320',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1321',
    name: 'ExfiltrationAttackTactics Rule #321',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1322',
    name: 'ExfiltrationAttackTactics Rule #322',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1323',
    name: 'ExfiltrationAttackTactics Rule #323',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1324',
    name: 'ExfiltrationAttackTactics Rule #324',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1325',
    name: 'ExfiltrationAttackTactics Rule #325',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1326',
    name: 'ExfiltrationAttackTactics Rule #326',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1327',
    name: 'ExfiltrationAttackTactics Rule #327',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1328',
    name: 'ExfiltrationAttackTactics Rule #328',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1329',
    name: 'ExfiltrationAttackTactics Rule #329',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1330',
    name: 'ExfiltrationAttackTactics Rule #330',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1331',
    name: 'ExfiltrationAttackTactics Rule #331',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1332',
    name: 'ExfiltrationAttackTactics Rule #332',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1333',
    name: 'ExfiltrationAttackTactics Rule #333',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1334',
    name: 'ExfiltrationAttackTactics Rule #334',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1335',
    name: 'ExfiltrationAttackTactics Rule #335',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1336',
    name: 'ExfiltrationAttackTactics Rule #336',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1337',
    name: 'ExfiltrationAttackTactics Rule #337',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1338',
    name: 'ExfiltrationAttackTactics Rule #338',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1339',
    name: 'ExfiltrationAttackTactics Rule #339',
    category: 'and scheduled egress',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1340',
    name: 'ExfiltrationAttackTactics Rule #340',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1341',
    name: 'ExfiltrationAttackTactics Rule #341',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1342',
    name: 'ExfiltrationAttackTactics Rule #342',
    category: 'ICMP tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1343',
    name: 'ExfiltrationAttackTactics Rule #343',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1344',
    name: 'ExfiltrationAttackTactics Rule #344',
    category: 'Exfiltration over cloud storage',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1345',
    name: 'ExfiltrationAttackTactics Rule #345',
    category: 'encrypted archive uploads',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1346',
    name: 'ExfiltrationAttackTactics Rule #346',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1347',
    name: 'ExfiltrationAttackTactics Rule #347',
    category: 'and scheduled egress',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1348',
    name: 'ExfiltrationAttackTactics Rule #348',
    category: 'Exfiltration over cloud storage',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1349',
    name: 'ExfiltrationAttackTactics Rule #349',
    category: 'encrypted archive uploads',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0011-T1350',
    name: 'ExfiltrationAttackTactics Rule #350',
    category: 'ICMP tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0011_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0011_DATASET.slice(0, 20);
    return MITRE_TA0011_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
