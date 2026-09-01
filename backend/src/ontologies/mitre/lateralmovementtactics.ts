/**
 * MITRE ATT&CK Enterprise Matrix: LateralMovementTactics
 * Threat Scope: Pass-the-Hash, SMB/PsExec execution, SSH hijacking, and RDP tunnel hopping
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

export const MITRE_TA0008_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0008-T1001',
    name: 'LateralMovementTactics Rule #1',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1002',
    name: 'LateralMovementTactics Rule #2',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1003',
    name: 'LateralMovementTactics Rule #3',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1004',
    name: 'LateralMovementTactics Rule #4',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1005',
    name: 'LateralMovementTactics Rule #5',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1006',
    name: 'LateralMovementTactics Rule #6',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1007',
    name: 'LateralMovementTactics Rule #7',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1008',
    name: 'LateralMovementTactics Rule #8',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1009',
    name: 'LateralMovementTactics Rule #9',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1010',
    name: 'LateralMovementTactics Rule #10',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1011',
    name: 'LateralMovementTactics Rule #11',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1012',
    name: 'LateralMovementTactics Rule #12',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1013',
    name: 'LateralMovementTactics Rule #13',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1014',
    name: 'LateralMovementTactics Rule #14',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1015',
    name: 'LateralMovementTactics Rule #15',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1016',
    name: 'LateralMovementTactics Rule #16',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1017',
    name: 'LateralMovementTactics Rule #17',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1018',
    name: 'LateralMovementTactics Rule #18',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1019',
    name: 'LateralMovementTactics Rule #19',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1020',
    name: 'LateralMovementTactics Rule #20',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1021',
    name: 'LateralMovementTactics Rule #21',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1022',
    name: 'LateralMovementTactics Rule #22',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1023',
    name: 'LateralMovementTactics Rule #23',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1024',
    name: 'LateralMovementTactics Rule #24',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1025',
    name: 'LateralMovementTactics Rule #25',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1026',
    name: 'LateralMovementTactics Rule #26',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1027',
    name: 'LateralMovementTactics Rule #27',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1028',
    name: 'LateralMovementTactics Rule #28',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1029',
    name: 'LateralMovementTactics Rule #29',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1030',
    name: 'LateralMovementTactics Rule #30',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1031',
    name: 'LateralMovementTactics Rule #31',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1032',
    name: 'LateralMovementTactics Rule #32',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1033',
    name: 'LateralMovementTactics Rule #33',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1034',
    name: 'LateralMovementTactics Rule #34',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1035',
    name: 'LateralMovementTactics Rule #35',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1036',
    name: 'LateralMovementTactics Rule #36',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1037',
    name: 'LateralMovementTactics Rule #37',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1038',
    name: 'LateralMovementTactics Rule #38',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1039',
    name: 'LateralMovementTactics Rule #39',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1040',
    name: 'LateralMovementTactics Rule #40',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1041',
    name: 'LateralMovementTactics Rule #41',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1042',
    name: 'LateralMovementTactics Rule #42',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1043',
    name: 'LateralMovementTactics Rule #43',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1044',
    name: 'LateralMovementTactics Rule #44',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1045',
    name: 'LateralMovementTactics Rule #45',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1046',
    name: 'LateralMovementTactics Rule #46',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1047',
    name: 'LateralMovementTactics Rule #47',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1048',
    name: 'LateralMovementTactics Rule #48',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1049',
    name: 'LateralMovementTactics Rule #49',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1050',
    name: 'LateralMovementTactics Rule #50',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1051',
    name: 'LateralMovementTactics Rule #51',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1052',
    name: 'LateralMovementTactics Rule #52',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1053',
    name: 'LateralMovementTactics Rule #53',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1054',
    name: 'LateralMovementTactics Rule #54',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1055',
    name: 'LateralMovementTactics Rule #55',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1056',
    name: 'LateralMovementTactics Rule #56',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1057',
    name: 'LateralMovementTactics Rule #57',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1058',
    name: 'LateralMovementTactics Rule #58',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1059',
    name: 'LateralMovementTactics Rule #59',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1060',
    name: 'LateralMovementTactics Rule #60',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1061',
    name: 'LateralMovementTactics Rule #61',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1062',
    name: 'LateralMovementTactics Rule #62',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1063',
    name: 'LateralMovementTactics Rule #63',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1064',
    name: 'LateralMovementTactics Rule #64',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1065',
    name: 'LateralMovementTactics Rule #65',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1066',
    name: 'LateralMovementTactics Rule #66',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1067',
    name: 'LateralMovementTactics Rule #67',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1068',
    name: 'LateralMovementTactics Rule #68',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1069',
    name: 'LateralMovementTactics Rule #69',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1070',
    name: 'LateralMovementTactics Rule #70',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1071',
    name: 'LateralMovementTactics Rule #71',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1072',
    name: 'LateralMovementTactics Rule #72',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1073',
    name: 'LateralMovementTactics Rule #73',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1074',
    name: 'LateralMovementTactics Rule #74',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1075',
    name: 'LateralMovementTactics Rule #75',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1076',
    name: 'LateralMovementTactics Rule #76',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1077',
    name: 'LateralMovementTactics Rule #77',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1078',
    name: 'LateralMovementTactics Rule #78',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1079',
    name: 'LateralMovementTactics Rule #79',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1080',
    name: 'LateralMovementTactics Rule #80',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1081',
    name: 'LateralMovementTactics Rule #81',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1082',
    name: 'LateralMovementTactics Rule #82',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1083',
    name: 'LateralMovementTactics Rule #83',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1084',
    name: 'LateralMovementTactics Rule #84',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1085',
    name: 'LateralMovementTactics Rule #85',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1086',
    name: 'LateralMovementTactics Rule #86',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1087',
    name: 'LateralMovementTactics Rule #87',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1088',
    name: 'LateralMovementTactics Rule #88',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1089',
    name: 'LateralMovementTactics Rule #89',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1090',
    name: 'LateralMovementTactics Rule #90',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1091',
    name: 'LateralMovementTactics Rule #91',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1092',
    name: 'LateralMovementTactics Rule #92',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1093',
    name: 'LateralMovementTactics Rule #93',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1094',
    name: 'LateralMovementTactics Rule #94',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1095',
    name: 'LateralMovementTactics Rule #95',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1096',
    name: 'LateralMovementTactics Rule #96',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1097',
    name: 'LateralMovementTactics Rule #97',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1098',
    name: 'LateralMovementTactics Rule #98',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1099',
    name: 'LateralMovementTactics Rule #99',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1100',
    name: 'LateralMovementTactics Rule #100',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1101',
    name: 'LateralMovementTactics Rule #101',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1102',
    name: 'LateralMovementTactics Rule #102',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1103',
    name: 'LateralMovementTactics Rule #103',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1104',
    name: 'LateralMovementTactics Rule #104',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1105',
    name: 'LateralMovementTactics Rule #105',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1106',
    name: 'LateralMovementTactics Rule #106',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1107',
    name: 'LateralMovementTactics Rule #107',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1108',
    name: 'LateralMovementTactics Rule #108',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1109',
    name: 'LateralMovementTactics Rule #109',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1110',
    name: 'LateralMovementTactics Rule #110',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1111',
    name: 'LateralMovementTactics Rule #111',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1112',
    name: 'LateralMovementTactics Rule #112',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1113',
    name: 'LateralMovementTactics Rule #113',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1114',
    name: 'LateralMovementTactics Rule #114',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1115',
    name: 'LateralMovementTactics Rule #115',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1116',
    name: 'LateralMovementTactics Rule #116',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1117',
    name: 'LateralMovementTactics Rule #117',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1118',
    name: 'LateralMovementTactics Rule #118',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1119',
    name: 'LateralMovementTactics Rule #119',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1120',
    name: 'LateralMovementTactics Rule #120',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1121',
    name: 'LateralMovementTactics Rule #121',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1122',
    name: 'LateralMovementTactics Rule #122',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1123',
    name: 'LateralMovementTactics Rule #123',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1124',
    name: 'LateralMovementTactics Rule #124',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1125',
    name: 'LateralMovementTactics Rule #125',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1126',
    name: 'LateralMovementTactics Rule #126',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1127',
    name: 'LateralMovementTactics Rule #127',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1128',
    name: 'LateralMovementTactics Rule #128',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1129',
    name: 'LateralMovementTactics Rule #129',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1130',
    name: 'LateralMovementTactics Rule #130',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1131',
    name: 'LateralMovementTactics Rule #131',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1132',
    name: 'LateralMovementTactics Rule #132',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1133',
    name: 'LateralMovementTactics Rule #133',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1134',
    name: 'LateralMovementTactics Rule #134',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1135',
    name: 'LateralMovementTactics Rule #135',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1136',
    name: 'LateralMovementTactics Rule #136',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1137',
    name: 'LateralMovementTactics Rule #137',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1138',
    name: 'LateralMovementTactics Rule #138',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1139',
    name: 'LateralMovementTactics Rule #139',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1140',
    name: 'LateralMovementTactics Rule #140',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1141',
    name: 'LateralMovementTactics Rule #141',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1142',
    name: 'LateralMovementTactics Rule #142',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1143',
    name: 'LateralMovementTactics Rule #143',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1144',
    name: 'LateralMovementTactics Rule #144',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1145',
    name: 'LateralMovementTactics Rule #145',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1146',
    name: 'LateralMovementTactics Rule #146',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1147',
    name: 'LateralMovementTactics Rule #147',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1148',
    name: 'LateralMovementTactics Rule #148',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1149',
    name: 'LateralMovementTactics Rule #149',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1150',
    name: 'LateralMovementTactics Rule #150',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1151',
    name: 'LateralMovementTactics Rule #151',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1152',
    name: 'LateralMovementTactics Rule #152',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1153',
    name: 'LateralMovementTactics Rule #153',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1154',
    name: 'LateralMovementTactics Rule #154',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1155',
    name: 'LateralMovementTactics Rule #155',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1156',
    name: 'LateralMovementTactics Rule #156',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1157',
    name: 'LateralMovementTactics Rule #157',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1158',
    name: 'LateralMovementTactics Rule #158',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1159',
    name: 'LateralMovementTactics Rule #159',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1160',
    name: 'LateralMovementTactics Rule #160',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1161',
    name: 'LateralMovementTactics Rule #161',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1162',
    name: 'LateralMovementTactics Rule #162',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1163',
    name: 'LateralMovementTactics Rule #163',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1164',
    name: 'LateralMovementTactics Rule #164',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1165',
    name: 'LateralMovementTactics Rule #165',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1166',
    name: 'LateralMovementTactics Rule #166',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1167',
    name: 'LateralMovementTactics Rule #167',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1168',
    name: 'LateralMovementTactics Rule #168',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1169',
    name: 'LateralMovementTactics Rule #169',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1170',
    name: 'LateralMovementTactics Rule #170',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1171',
    name: 'LateralMovementTactics Rule #171',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1172',
    name: 'LateralMovementTactics Rule #172',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1173',
    name: 'LateralMovementTactics Rule #173',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1174',
    name: 'LateralMovementTactics Rule #174',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1175',
    name: 'LateralMovementTactics Rule #175',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1176',
    name: 'LateralMovementTactics Rule #176',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1177',
    name: 'LateralMovementTactics Rule #177',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1178',
    name: 'LateralMovementTactics Rule #178',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1179',
    name: 'LateralMovementTactics Rule #179',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1180',
    name: 'LateralMovementTactics Rule #180',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1181',
    name: 'LateralMovementTactics Rule #181',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1182',
    name: 'LateralMovementTactics Rule #182',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1183',
    name: 'LateralMovementTactics Rule #183',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1184',
    name: 'LateralMovementTactics Rule #184',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1185',
    name: 'LateralMovementTactics Rule #185',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1186',
    name: 'LateralMovementTactics Rule #186',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1187',
    name: 'LateralMovementTactics Rule #187',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1188',
    name: 'LateralMovementTactics Rule #188',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1189',
    name: 'LateralMovementTactics Rule #189',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1190',
    name: 'LateralMovementTactics Rule #190',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1191',
    name: 'LateralMovementTactics Rule #191',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1192',
    name: 'LateralMovementTactics Rule #192',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1193',
    name: 'LateralMovementTactics Rule #193',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1194',
    name: 'LateralMovementTactics Rule #194',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1195',
    name: 'LateralMovementTactics Rule #195',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1196',
    name: 'LateralMovementTactics Rule #196',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1197',
    name: 'LateralMovementTactics Rule #197',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1198',
    name: 'LateralMovementTactics Rule #198',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1199',
    name: 'LateralMovementTactics Rule #199',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1200',
    name: 'LateralMovementTactics Rule #200',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1201',
    name: 'LateralMovementTactics Rule #201',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1202',
    name: 'LateralMovementTactics Rule #202',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1203',
    name: 'LateralMovementTactics Rule #203',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1204',
    name: 'LateralMovementTactics Rule #204',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1205',
    name: 'LateralMovementTactics Rule #205',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1206',
    name: 'LateralMovementTactics Rule #206',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1207',
    name: 'LateralMovementTactics Rule #207',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1208',
    name: 'LateralMovementTactics Rule #208',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1209',
    name: 'LateralMovementTactics Rule #209',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1210',
    name: 'LateralMovementTactics Rule #210',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1211',
    name: 'LateralMovementTactics Rule #211',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1212',
    name: 'LateralMovementTactics Rule #212',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1213',
    name: 'LateralMovementTactics Rule #213',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1214',
    name: 'LateralMovementTactics Rule #214',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1215',
    name: 'LateralMovementTactics Rule #215',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1216',
    name: 'LateralMovementTactics Rule #216',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1217',
    name: 'LateralMovementTactics Rule #217',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1218',
    name: 'LateralMovementTactics Rule #218',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1219',
    name: 'LateralMovementTactics Rule #219',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1220',
    name: 'LateralMovementTactics Rule #220',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1221',
    name: 'LateralMovementTactics Rule #221',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1222',
    name: 'LateralMovementTactics Rule #222',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1223',
    name: 'LateralMovementTactics Rule #223',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1224',
    name: 'LateralMovementTactics Rule #224',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1225',
    name: 'LateralMovementTactics Rule #225',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1226',
    name: 'LateralMovementTactics Rule #226',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1227',
    name: 'LateralMovementTactics Rule #227',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1228',
    name: 'LateralMovementTactics Rule #228',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1229',
    name: 'LateralMovementTactics Rule #229',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1230',
    name: 'LateralMovementTactics Rule #230',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1231',
    name: 'LateralMovementTactics Rule #231',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1232',
    name: 'LateralMovementTactics Rule #232',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1233',
    name: 'LateralMovementTactics Rule #233',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1234',
    name: 'LateralMovementTactics Rule #234',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1235',
    name: 'LateralMovementTactics Rule #235',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1236',
    name: 'LateralMovementTactics Rule #236',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1237',
    name: 'LateralMovementTactics Rule #237',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1238',
    name: 'LateralMovementTactics Rule #238',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1239',
    name: 'LateralMovementTactics Rule #239',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1240',
    name: 'LateralMovementTactics Rule #240',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1241',
    name: 'LateralMovementTactics Rule #241',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1242',
    name: 'LateralMovementTactics Rule #242',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1243',
    name: 'LateralMovementTactics Rule #243',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1244',
    name: 'LateralMovementTactics Rule #244',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1245',
    name: 'LateralMovementTactics Rule #245',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1246',
    name: 'LateralMovementTactics Rule #246',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1247',
    name: 'LateralMovementTactics Rule #247',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1248',
    name: 'LateralMovementTactics Rule #248',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1249',
    name: 'LateralMovementTactics Rule #249',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1250',
    name: 'LateralMovementTactics Rule #250',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1251',
    name: 'LateralMovementTactics Rule #251',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1252',
    name: 'LateralMovementTactics Rule #252',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1253',
    name: 'LateralMovementTactics Rule #253',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1254',
    name: 'LateralMovementTactics Rule #254',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1255',
    name: 'LateralMovementTactics Rule #255',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1256',
    name: 'LateralMovementTactics Rule #256',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1257',
    name: 'LateralMovementTactics Rule #257',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1258',
    name: 'LateralMovementTactics Rule #258',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1259',
    name: 'LateralMovementTactics Rule #259',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1260',
    name: 'LateralMovementTactics Rule #260',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1261',
    name: 'LateralMovementTactics Rule #261',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1262',
    name: 'LateralMovementTactics Rule #262',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1263',
    name: 'LateralMovementTactics Rule #263',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1264',
    name: 'LateralMovementTactics Rule #264',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1265',
    name: 'LateralMovementTactics Rule #265',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1266',
    name: 'LateralMovementTactics Rule #266',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1267',
    name: 'LateralMovementTactics Rule #267',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1268',
    name: 'LateralMovementTactics Rule #268',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1269',
    name: 'LateralMovementTactics Rule #269',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1270',
    name: 'LateralMovementTactics Rule #270',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1271',
    name: 'LateralMovementTactics Rule #271',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1272',
    name: 'LateralMovementTactics Rule #272',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1273',
    name: 'LateralMovementTactics Rule #273',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1274',
    name: 'LateralMovementTactics Rule #274',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1275',
    name: 'LateralMovementTactics Rule #275',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1276',
    name: 'LateralMovementTactics Rule #276',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1277',
    name: 'LateralMovementTactics Rule #277',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1278',
    name: 'LateralMovementTactics Rule #278',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1279',
    name: 'LateralMovementTactics Rule #279',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1280',
    name: 'LateralMovementTactics Rule #280',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1281',
    name: 'LateralMovementTactics Rule #281',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1282',
    name: 'LateralMovementTactics Rule #282',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1283',
    name: 'LateralMovementTactics Rule #283',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1284',
    name: 'LateralMovementTactics Rule #284',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1285',
    name: 'LateralMovementTactics Rule #285',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1286',
    name: 'LateralMovementTactics Rule #286',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1287',
    name: 'LateralMovementTactics Rule #287',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1288',
    name: 'LateralMovementTactics Rule #288',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1289',
    name: 'LateralMovementTactics Rule #289',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1290',
    name: 'LateralMovementTactics Rule #290',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1291',
    name: 'LateralMovementTactics Rule #291',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1292',
    name: 'LateralMovementTactics Rule #292',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1293',
    name: 'LateralMovementTactics Rule #293',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1294',
    name: 'LateralMovementTactics Rule #294',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1295',
    name: 'LateralMovementTactics Rule #295',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1296',
    name: 'LateralMovementTactics Rule #296',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1297',
    name: 'LateralMovementTactics Rule #297',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1298',
    name: 'LateralMovementTactics Rule #298',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1299',
    name: 'LateralMovementTactics Rule #299',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1300',
    name: 'LateralMovementTactics Rule #300',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1301',
    name: 'LateralMovementTactics Rule #301',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1302',
    name: 'LateralMovementTactics Rule #302',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1303',
    name: 'LateralMovementTactics Rule #303',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1304',
    name: 'LateralMovementTactics Rule #304',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1305',
    name: 'LateralMovementTactics Rule #305',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1306',
    name: 'LateralMovementTactics Rule #306',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1307',
    name: 'LateralMovementTactics Rule #307',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1308',
    name: 'LateralMovementTactics Rule #308',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1309',
    name: 'LateralMovementTactics Rule #309',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1310',
    name: 'LateralMovementTactics Rule #310',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1311',
    name: 'LateralMovementTactics Rule #311',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1312',
    name: 'LateralMovementTactics Rule #312',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1313',
    name: 'LateralMovementTactics Rule #313',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1314',
    name: 'LateralMovementTactics Rule #314',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1315',
    name: 'LateralMovementTactics Rule #315',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1316',
    name: 'LateralMovementTactics Rule #316',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1317',
    name: 'LateralMovementTactics Rule #317',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1318',
    name: 'LateralMovementTactics Rule #318',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1319',
    name: 'LateralMovementTactics Rule #319',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1320',
    name: 'LateralMovementTactics Rule #320',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1321',
    name: 'LateralMovementTactics Rule #321',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1322',
    name: 'LateralMovementTactics Rule #322',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1323',
    name: 'LateralMovementTactics Rule #323',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1324',
    name: 'LateralMovementTactics Rule #324',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1325',
    name: 'LateralMovementTactics Rule #325',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1326',
    name: 'LateralMovementTactics Rule #326',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1327',
    name: 'LateralMovementTactics Rule #327',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1328',
    name: 'LateralMovementTactics Rule #328',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1329',
    name: 'LateralMovementTactics Rule #329',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1330',
    name: 'LateralMovementTactics Rule #330',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1331',
    name: 'LateralMovementTactics Rule #331',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1332',
    name: 'LateralMovementTactics Rule #332',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1333',
    name: 'LateralMovementTactics Rule #333',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1334',
    name: 'LateralMovementTactics Rule #334',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1335',
    name: 'LateralMovementTactics Rule #335',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1336',
    name: 'LateralMovementTactics Rule #336',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1337',
    name: 'LateralMovementTactics Rule #337',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1338',
    name: 'LateralMovementTactics Rule #338',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1339',
    name: 'LateralMovementTactics Rule #339',
    category: 'and RDP tunnel hopping',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1340',
    name: 'LateralMovementTactics Rule #340',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1341',
    name: 'LateralMovementTactics Rule #341',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1342',
    name: 'LateralMovementTactics Rule #342',
    category: 'SSH hijacking',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1343',
    name: 'LateralMovementTactics Rule #343',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1344',
    name: 'LateralMovementTactics Rule #344',
    category: 'Pass-the-Hash',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1345',
    name: 'LateralMovementTactics Rule #345',
    category: 'SMB/PsExec execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1346',
    name: 'LateralMovementTactics Rule #346',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1347',
    name: 'LateralMovementTactics Rule #347',
    category: 'and RDP tunnel hopping',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1348',
    name: 'LateralMovementTactics Rule #348',
    category: 'Pass-the-Hash',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1349',
    name: 'LateralMovementTactics Rule #349',
    category: 'SMB/PsExec execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0008-T1350',
    name: 'LateralMovementTactics Rule #350',
    category: 'SSH hijacking',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0008_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0008_DATASET.slice(0, 20);
    return MITRE_TA0008_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
