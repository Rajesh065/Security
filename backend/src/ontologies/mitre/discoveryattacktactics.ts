/**
 * MITRE ATT&CK Enterprise Matrix: DiscoveryAttackTactics
 * Threat Scope: Network service scanning, Active Directory domain enumeration, cloud resource enumeration
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

export const MITRE_TA0007_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0007-T1001',
    name: 'DiscoveryAttackTactics Rule #1',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1002',
    name: 'DiscoveryAttackTactics Rule #2',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1003',
    name: 'DiscoveryAttackTactics Rule #3',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1004',
    name: 'DiscoveryAttackTactics Rule #4',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1005',
    name: 'DiscoveryAttackTactics Rule #5',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1006',
    name: 'DiscoveryAttackTactics Rule #6',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1007',
    name: 'DiscoveryAttackTactics Rule #7',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1008',
    name: 'DiscoveryAttackTactics Rule #8',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1009',
    name: 'DiscoveryAttackTactics Rule #9',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1010',
    name: 'DiscoveryAttackTactics Rule #10',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1011',
    name: 'DiscoveryAttackTactics Rule #11',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1012',
    name: 'DiscoveryAttackTactics Rule #12',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1013',
    name: 'DiscoveryAttackTactics Rule #13',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1014',
    name: 'DiscoveryAttackTactics Rule #14',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1015',
    name: 'DiscoveryAttackTactics Rule #15',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1016',
    name: 'DiscoveryAttackTactics Rule #16',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1017',
    name: 'DiscoveryAttackTactics Rule #17',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1018',
    name: 'DiscoveryAttackTactics Rule #18',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1019',
    name: 'DiscoveryAttackTactics Rule #19',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1020',
    name: 'DiscoveryAttackTactics Rule #20',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1021',
    name: 'DiscoveryAttackTactics Rule #21',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1022',
    name: 'DiscoveryAttackTactics Rule #22',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1023',
    name: 'DiscoveryAttackTactics Rule #23',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1024',
    name: 'DiscoveryAttackTactics Rule #24',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1025',
    name: 'DiscoveryAttackTactics Rule #25',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1026',
    name: 'DiscoveryAttackTactics Rule #26',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1027',
    name: 'DiscoveryAttackTactics Rule #27',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1028',
    name: 'DiscoveryAttackTactics Rule #28',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1029',
    name: 'DiscoveryAttackTactics Rule #29',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1030',
    name: 'DiscoveryAttackTactics Rule #30',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1031',
    name: 'DiscoveryAttackTactics Rule #31',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1032',
    name: 'DiscoveryAttackTactics Rule #32',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1033',
    name: 'DiscoveryAttackTactics Rule #33',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1034',
    name: 'DiscoveryAttackTactics Rule #34',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1035',
    name: 'DiscoveryAttackTactics Rule #35',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1036',
    name: 'DiscoveryAttackTactics Rule #36',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1037',
    name: 'DiscoveryAttackTactics Rule #37',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1038',
    name: 'DiscoveryAttackTactics Rule #38',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1039',
    name: 'DiscoveryAttackTactics Rule #39',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1040',
    name: 'DiscoveryAttackTactics Rule #40',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1041',
    name: 'DiscoveryAttackTactics Rule #41',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1042',
    name: 'DiscoveryAttackTactics Rule #42',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1043',
    name: 'DiscoveryAttackTactics Rule #43',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1044',
    name: 'DiscoveryAttackTactics Rule #44',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1045',
    name: 'DiscoveryAttackTactics Rule #45',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1046',
    name: 'DiscoveryAttackTactics Rule #46',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1047',
    name: 'DiscoveryAttackTactics Rule #47',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1048',
    name: 'DiscoveryAttackTactics Rule #48',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1049',
    name: 'DiscoveryAttackTactics Rule #49',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1050',
    name: 'DiscoveryAttackTactics Rule #50',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1051',
    name: 'DiscoveryAttackTactics Rule #51',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1052',
    name: 'DiscoveryAttackTactics Rule #52',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1053',
    name: 'DiscoveryAttackTactics Rule #53',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1054',
    name: 'DiscoveryAttackTactics Rule #54',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1055',
    name: 'DiscoveryAttackTactics Rule #55',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1056',
    name: 'DiscoveryAttackTactics Rule #56',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1057',
    name: 'DiscoveryAttackTactics Rule #57',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1058',
    name: 'DiscoveryAttackTactics Rule #58',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1059',
    name: 'DiscoveryAttackTactics Rule #59',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1060',
    name: 'DiscoveryAttackTactics Rule #60',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1061',
    name: 'DiscoveryAttackTactics Rule #61',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1062',
    name: 'DiscoveryAttackTactics Rule #62',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1063',
    name: 'DiscoveryAttackTactics Rule #63',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1064',
    name: 'DiscoveryAttackTactics Rule #64',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1065',
    name: 'DiscoveryAttackTactics Rule #65',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1066',
    name: 'DiscoveryAttackTactics Rule #66',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1067',
    name: 'DiscoveryAttackTactics Rule #67',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1068',
    name: 'DiscoveryAttackTactics Rule #68',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1069',
    name: 'DiscoveryAttackTactics Rule #69',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1070',
    name: 'DiscoveryAttackTactics Rule #70',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1071',
    name: 'DiscoveryAttackTactics Rule #71',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1072',
    name: 'DiscoveryAttackTactics Rule #72',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1073',
    name: 'DiscoveryAttackTactics Rule #73',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1074',
    name: 'DiscoveryAttackTactics Rule #74',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1075',
    name: 'DiscoveryAttackTactics Rule #75',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1076',
    name: 'DiscoveryAttackTactics Rule #76',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1077',
    name: 'DiscoveryAttackTactics Rule #77',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1078',
    name: 'DiscoveryAttackTactics Rule #78',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1079',
    name: 'DiscoveryAttackTactics Rule #79',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1080',
    name: 'DiscoveryAttackTactics Rule #80',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1081',
    name: 'DiscoveryAttackTactics Rule #81',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1082',
    name: 'DiscoveryAttackTactics Rule #82',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1083',
    name: 'DiscoveryAttackTactics Rule #83',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1084',
    name: 'DiscoveryAttackTactics Rule #84',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1085',
    name: 'DiscoveryAttackTactics Rule #85',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1086',
    name: 'DiscoveryAttackTactics Rule #86',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1087',
    name: 'DiscoveryAttackTactics Rule #87',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1088',
    name: 'DiscoveryAttackTactics Rule #88',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1089',
    name: 'DiscoveryAttackTactics Rule #89',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1090',
    name: 'DiscoveryAttackTactics Rule #90',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1091',
    name: 'DiscoveryAttackTactics Rule #91',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1092',
    name: 'DiscoveryAttackTactics Rule #92',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1093',
    name: 'DiscoveryAttackTactics Rule #93',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1094',
    name: 'DiscoveryAttackTactics Rule #94',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1095',
    name: 'DiscoveryAttackTactics Rule #95',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1096',
    name: 'DiscoveryAttackTactics Rule #96',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1097',
    name: 'DiscoveryAttackTactics Rule #97',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1098',
    name: 'DiscoveryAttackTactics Rule #98',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1099',
    name: 'DiscoveryAttackTactics Rule #99',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1100',
    name: 'DiscoveryAttackTactics Rule #100',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1101',
    name: 'DiscoveryAttackTactics Rule #101',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1102',
    name: 'DiscoveryAttackTactics Rule #102',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1103',
    name: 'DiscoveryAttackTactics Rule #103',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1104',
    name: 'DiscoveryAttackTactics Rule #104',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1105',
    name: 'DiscoveryAttackTactics Rule #105',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1106',
    name: 'DiscoveryAttackTactics Rule #106',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1107',
    name: 'DiscoveryAttackTactics Rule #107',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1108',
    name: 'DiscoveryAttackTactics Rule #108',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1109',
    name: 'DiscoveryAttackTactics Rule #109',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1110',
    name: 'DiscoveryAttackTactics Rule #110',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1111',
    name: 'DiscoveryAttackTactics Rule #111',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1112',
    name: 'DiscoveryAttackTactics Rule #112',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1113',
    name: 'DiscoveryAttackTactics Rule #113',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1114',
    name: 'DiscoveryAttackTactics Rule #114',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1115',
    name: 'DiscoveryAttackTactics Rule #115',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1116',
    name: 'DiscoveryAttackTactics Rule #116',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1117',
    name: 'DiscoveryAttackTactics Rule #117',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1118',
    name: 'DiscoveryAttackTactics Rule #118',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1119',
    name: 'DiscoveryAttackTactics Rule #119',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1120',
    name: 'DiscoveryAttackTactics Rule #120',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1121',
    name: 'DiscoveryAttackTactics Rule #121',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1122',
    name: 'DiscoveryAttackTactics Rule #122',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1123',
    name: 'DiscoveryAttackTactics Rule #123',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1124',
    name: 'DiscoveryAttackTactics Rule #124',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1125',
    name: 'DiscoveryAttackTactics Rule #125',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1126',
    name: 'DiscoveryAttackTactics Rule #126',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1127',
    name: 'DiscoveryAttackTactics Rule #127',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1128',
    name: 'DiscoveryAttackTactics Rule #128',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1129',
    name: 'DiscoveryAttackTactics Rule #129',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1130',
    name: 'DiscoveryAttackTactics Rule #130',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1131',
    name: 'DiscoveryAttackTactics Rule #131',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1132',
    name: 'DiscoveryAttackTactics Rule #132',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1133',
    name: 'DiscoveryAttackTactics Rule #133',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1134',
    name: 'DiscoveryAttackTactics Rule #134',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1135',
    name: 'DiscoveryAttackTactics Rule #135',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1136',
    name: 'DiscoveryAttackTactics Rule #136',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1137',
    name: 'DiscoveryAttackTactics Rule #137',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1138',
    name: 'DiscoveryAttackTactics Rule #138',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1139',
    name: 'DiscoveryAttackTactics Rule #139',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1140',
    name: 'DiscoveryAttackTactics Rule #140',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1141',
    name: 'DiscoveryAttackTactics Rule #141',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1142',
    name: 'DiscoveryAttackTactics Rule #142',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1143',
    name: 'DiscoveryAttackTactics Rule #143',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1144',
    name: 'DiscoveryAttackTactics Rule #144',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1145',
    name: 'DiscoveryAttackTactics Rule #145',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1146',
    name: 'DiscoveryAttackTactics Rule #146',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1147',
    name: 'DiscoveryAttackTactics Rule #147',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1148',
    name: 'DiscoveryAttackTactics Rule #148',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1149',
    name: 'DiscoveryAttackTactics Rule #149',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1150',
    name: 'DiscoveryAttackTactics Rule #150',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1151',
    name: 'DiscoveryAttackTactics Rule #151',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1152',
    name: 'DiscoveryAttackTactics Rule #152',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1153',
    name: 'DiscoveryAttackTactics Rule #153',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1154',
    name: 'DiscoveryAttackTactics Rule #154',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1155',
    name: 'DiscoveryAttackTactics Rule #155',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1156',
    name: 'DiscoveryAttackTactics Rule #156',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1157',
    name: 'DiscoveryAttackTactics Rule #157',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1158',
    name: 'DiscoveryAttackTactics Rule #158',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1159',
    name: 'DiscoveryAttackTactics Rule #159',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1160',
    name: 'DiscoveryAttackTactics Rule #160',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1161',
    name: 'DiscoveryAttackTactics Rule #161',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1162',
    name: 'DiscoveryAttackTactics Rule #162',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1163',
    name: 'DiscoveryAttackTactics Rule #163',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1164',
    name: 'DiscoveryAttackTactics Rule #164',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1165',
    name: 'DiscoveryAttackTactics Rule #165',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1166',
    name: 'DiscoveryAttackTactics Rule #166',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1167',
    name: 'DiscoveryAttackTactics Rule #167',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1168',
    name: 'DiscoveryAttackTactics Rule #168',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1169',
    name: 'DiscoveryAttackTactics Rule #169',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1170',
    name: 'DiscoveryAttackTactics Rule #170',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1171',
    name: 'DiscoveryAttackTactics Rule #171',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1172',
    name: 'DiscoveryAttackTactics Rule #172',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1173',
    name: 'DiscoveryAttackTactics Rule #173',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1174',
    name: 'DiscoveryAttackTactics Rule #174',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1175',
    name: 'DiscoveryAttackTactics Rule #175',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1176',
    name: 'DiscoveryAttackTactics Rule #176',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1177',
    name: 'DiscoveryAttackTactics Rule #177',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1178',
    name: 'DiscoveryAttackTactics Rule #178',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1179',
    name: 'DiscoveryAttackTactics Rule #179',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1180',
    name: 'DiscoveryAttackTactics Rule #180',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1181',
    name: 'DiscoveryAttackTactics Rule #181',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1182',
    name: 'DiscoveryAttackTactics Rule #182',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1183',
    name: 'DiscoveryAttackTactics Rule #183',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1184',
    name: 'DiscoveryAttackTactics Rule #184',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1185',
    name: 'DiscoveryAttackTactics Rule #185',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1186',
    name: 'DiscoveryAttackTactics Rule #186',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1187',
    name: 'DiscoveryAttackTactics Rule #187',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1188',
    name: 'DiscoveryAttackTactics Rule #188',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1189',
    name: 'DiscoveryAttackTactics Rule #189',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1190',
    name: 'DiscoveryAttackTactics Rule #190',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1191',
    name: 'DiscoveryAttackTactics Rule #191',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1192',
    name: 'DiscoveryAttackTactics Rule #192',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1193',
    name: 'DiscoveryAttackTactics Rule #193',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1194',
    name: 'DiscoveryAttackTactics Rule #194',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1195',
    name: 'DiscoveryAttackTactics Rule #195',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1196',
    name: 'DiscoveryAttackTactics Rule #196',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1197',
    name: 'DiscoveryAttackTactics Rule #197',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1198',
    name: 'DiscoveryAttackTactics Rule #198',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1199',
    name: 'DiscoveryAttackTactics Rule #199',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1200',
    name: 'DiscoveryAttackTactics Rule #200',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1201',
    name: 'DiscoveryAttackTactics Rule #201',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1202',
    name: 'DiscoveryAttackTactics Rule #202',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1203',
    name: 'DiscoveryAttackTactics Rule #203',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1204',
    name: 'DiscoveryAttackTactics Rule #204',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1205',
    name: 'DiscoveryAttackTactics Rule #205',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1206',
    name: 'DiscoveryAttackTactics Rule #206',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1207',
    name: 'DiscoveryAttackTactics Rule #207',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1208',
    name: 'DiscoveryAttackTactics Rule #208',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1209',
    name: 'DiscoveryAttackTactics Rule #209',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1210',
    name: 'DiscoveryAttackTactics Rule #210',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1211',
    name: 'DiscoveryAttackTactics Rule #211',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1212',
    name: 'DiscoveryAttackTactics Rule #212',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1213',
    name: 'DiscoveryAttackTactics Rule #213',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1214',
    name: 'DiscoveryAttackTactics Rule #214',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1215',
    name: 'DiscoveryAttackTactics Rule #215',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1216',
    name: 'DiscoveryAttackTactics Rule #216',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1217',
    name: 'DiscoveryAttackTactics Rule #217',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1218',
    name: 'DiscoveryAttackTactics Rule #218',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1219',
    name: 'DiscoveryAttackTactics Rule #219',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1220',
    name: 'DiscoveryAttackTactics Rule #220',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1221',
    name: 'DiscoveryAttackTactics Rule #221',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1222',
    name: 'DiscoveryAttackTactics Rule #222',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1223',
    name: 'DiscoveryAttackTactics Rule #223',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1224',
    name: 'DiscoveryAttackTactics Rule #224',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1225',
    name: 'DiscoveryAttackTactics Rule #225',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1226',
    name: 'DiscoveryAttackTactics Rule #226',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1227',
    name: 'DiscoveryAttackTactics Rule #227',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1228',
    name: 'DiscoveryAttackTactics Rule #228',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1229',
    name: 'DiscoveryAttackTactics Rule #229',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1230',
    name: 'DiscoveryAttackTactics Rule #230',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1231',
    name: 'DiscoveryAttackTactics Rule #231',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1232',
    name: 'DiscoveryAttackTactics Rule #232',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1233',
    name: 'DiscoveryAttackTactics Rule #233',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1234',
    name: 'DiscoveryAttackTactics Rule #234',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1235',
    name: 'DiscoveryAttackTactics Rule #235',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1236',
    name: 'DiscoveryAttackTactics Rule #236',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1237',
    name: 'DiscoveryAttackTactics Rule #237',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1238',
    name: 'DiscoveryAttackTactics Rule #238',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1239',
    name: 'DiscoveryAttackTactics Rule #239',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1240',
    name: 'DiscoveryAttackTactics Rule #240',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1241',
    name: 'DiscoveryAttackTactics Rule #241',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1242',
    name: 'DiscoveryAttackTactics Rule #242',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1243',
    name: 'DiscoveryAttackTactics Rule #243',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1244',
    name: 'DiscoveryAttackTactics Rule #244',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1245',
    name: 'DiscoveryAttackTactics Rule #245',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1246',
    name: 'DiscoveryAttackTactics Rule #246',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1247',
    name: 'DiscoveryAttackTactics Rule #247',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1248',
    name: 'DiscoveryAttackTactics Rule #248',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1249',
    name: 'DiscoveryAttackTactics Rule #249',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1250',
    name: 'DiscoveryAttackTactics Rule #250',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1251',
    name: 'DiscoveryAttackTactics Rule #251',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1252',
    name: 'DiscoveryAttackTactics Rule #252',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1253',
    name: 'DiscoveryAttackTactics Rule #253',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1254',
    name: 'DiscoveryAttackTactics Rule #254',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1255',
    name: 'DiscoveryAttackTactics Rule #255',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1256',
    name: 'DiscoveryAttackTactics Rule #256',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1257',
    name: 'DiscoveryAttackTactics Rule #257',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1258',
    name: 'DiscoveryAttackTactics Rule #258',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1259',
    name: 'DiscoveryAttackTactics Rule #259',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1260',
    name: 'DiscoveryAttackTactics Rule #260',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1261',
    name: 'DiscoveryAttackTactics Rule #261',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1262',
    name: 'DiscoveryAttackTactics Rule #262',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1263',
    name: 'DiscoveryAttackTactics Rule #263',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1264',
    name: 'DiscoveryAttackTactics Rule #264',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1265',
    name: 'DiscoveryAttackTactics Rule #265',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1266',
    name: 'DiscoveryAttackTactics Rule #266',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1267',
    name: 'DiscoveryAttackTactics Rule #267',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1268',
    name: 'DiscoveryAttackTactics Rule #268',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1269',
    name: 'DiscoveryAttackTactics Rule #269',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1270',
    name: 'DiscoveryAttackTactics Rule #270',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1271',
    name: 'DiscoveryAttackTactics Rule #271',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1272',
    name: 'DiscoveryAttackTactics Rule #272',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1273',
    name: 'DiscoveryAttackTactics Rule #273',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1274',
    name: 'DiscoveryAttackTactics Rule #274',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1275',
    name: 'DiscoveryAttackTactics Rule #275',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1276',
    name: 'DiscoveryAttackTactics Rule #276',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1277',
    name: 'DiscoveryAttackTactics Rule #277',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1278',
    name: 'DiscoveryAttackTactics Rule #278',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1279',
    name: 'DiscoveryAttackTactics Rule #279',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1280',
    name: 'DiscoveryAttackTactics Rule #280',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1281',
    name: 'DiscoveryAttackTactics Rule #281',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1282',
    name: 'DiscoveryAttackTactics Rule #282',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1283',
    name: 'DiscoveryAttackTactics Rule #283',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1284',
    name: 'DiscoveryAttackTactics Rule #284',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1285',
    name: 'DiscoveryAttackTactics Rule #285',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1286',
    name: 'DiscoveryAttackTactics Rule #286',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1287',
    name: 'DiscoveryAttackTactics Rule #287',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1288',
    name: 'DiscoveryAttackTactics Rule #288',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1289',
    name: 'DiscoveryAttackTactics Rule #289',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1290',
    name: 'DiscoveryAttackTactics Rule #290',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1291',
    name: 'DiscoveryAttackTactics Rule #291',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1292',
    name: 'DiscoveryAttackTactics Rule #292',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1293',
    name: 'DiscoveryAttackTactics Rule #293',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1294',
    name: 'DiscoveryAttackTactics Rule #294',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1295',
    name: 'DiscoveryAttackTactics Rule #295',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1296',
    name: 'DiscoveryAttackTactics Rule #296',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1297',
    name: 'DiscoveryAttackTactics Rule #297',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1298',
    name: 'DiscoveryAttackTactics Rule #298',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1299',
    name: 'DiscoveryAttackTactics Rule #299',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1300',
    name: 'DiscoveryAttackTactics Rule #300',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1301',
    name: 'DiscoveryAttackTactics Rule #301',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1302',
    name: 'DiscoveryAttackTactics Rule #302',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1303',
    name: 'DiscoveryAttackTactics Rule #303',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1304',
    name: 'DiscoveryAttackTactics Rule #304',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1305',
    name: 'DiscoveryAttackTactics Rule #305',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1306',
    name: 'DiscoveryAttackTactics Rule #306',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1307',
    name: 'DiscoveryAttackTactics Rule #307',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1308',
    name: 'DiscoveryAttackTactics Rule #308',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1309',
    name: 'DiscoveryAttackTactics Rule #309',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1310',
    name: 'DiscoveryAttackTactics Rule #310',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1311',
    name: 'DiscoveryAttackTactics Rule #311',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1312',
    name: 'DiscoveryAttackTactics Rule #312',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1313',
    name: 'DiscoveryAttackTactics Rule #313',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1314',
    name: 'DiscoveryAttackTactics Rule #314',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1315',
    name: 'DiscoveryAttackTactics Rule #315',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1316',
    name: 'DiscoveryAttackTactics Rule #316',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1317',
    name: 'DiscoveryAttackTactics Rule #317',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1318',
    name: 'DiscoveryAttackTactics Rule #318',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1319',
    name: 'DiscoveryAttackTactics Rule #319',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1320',
    name: 'DiscoveryAttackTactics Rule #320',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1321',
    name: 'DiscoveryAttackTactics Rule #321',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1322',
    name: 'DiscoveryAttackTactics Rule #322',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1323',
    name: 'DiscoveryAttackTactics Rule #323',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1324',
    name: 'DiscoveryAttackTactics Rule #324',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1325',
    name: 'DiscoveryAttackTactics Rule #325',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1326',
    name: 'DiscoveryAttackTactics Rule #326',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1327',
    name: 'DiscoveryAttackTactics Rule #327',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1328',
    name: 'DiscoveryAttackTactics Rule #328',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1329',
    name: 'DiscoveryAttackTactics Rule #329',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1330',
    name: 'DiscoveryAttackTactics Rule #330',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1331',
    name: 'DiscoveryAttackTactics Rule #331',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1332',
    name: 'DiscoveryAttackTactics Rule #332',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1333',
    name: 'DiscoveryAttackTactics Rule #333',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1334',
    name: 'DiscoveryAttackTactics Rule #334',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1335',
    name: 'DiscoveryAttackTactics Rule #335',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1336',
    name: 'DiscoveryAttackTactics Rule #336',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1337',
    name: 'DiscoveryAttackTactics Rule #337',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1338',
    name: 'DiscoveryAttackTactics Rule #338',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1339',
    name: 'DiscoveryAttackTactics Rule #339',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1340',
    name: 'DiscoveryAttackTactics Rule #340',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1341',
    name: 'DiscoveryAttackTactics Rule #341',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1342',
    name: 'DiscoveryAttackTactics Rule #342',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1343',
    name: 'DiscoveryAttackTactics Rule #343',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1344',
    name: 'DiscoveryAttackTactics Rule #344',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1345',
    name: 'DiscoveryAttackTactics Rule #345',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1346',
    name: 'DiscoveryAttackTactics Rule #346',
    category: 'Active Directory domain enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1347',
    name: 'DiscoveryAttackTactics Rule #347',
    category: 'cloud resource enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1348',
    name: 'DiscoveryAttackTactics Rule #348',
    category: 'Network service scanning',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1349',
    name: 'DiscoveryAttackTactics Rule #349',
    category: 'Active Directory domain enumeration',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0007-T1350',
    name: 'DiscoveryAttackTactics Rule #350',
    category: 'cloud resource enumeration',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0007_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0007_DATASET.slice(0, 20);
    return MITRE_TA0007_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
