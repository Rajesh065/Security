/**
 * MITRE ATT&CK Enterprise Matrix: ExecutionAttackTactics
 * Threat Scope: PowerShell encoded scripts, Windows Command Shell, WMI process creation, and serverless execution
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

export const MITRE_TA0002_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0002-T1001',
    name: 'ExecutionAttackTactics Rule #1',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1002',
    name: 'ExecutionAttackTactics Rule #2',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1003',
    name: 'ExecutionAttackTactics Rule #3',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1004',
    name: 'ExecutionAttackTactics Rule #4',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1005',
    name: 'ExecutionAttackTactics Rule #5',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1006',
    name: 'ExecutionAttackTactics Rule #6',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1007',
    name: 'ExecutionAttackTactics Rule #7',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1008',
    name: 'ExecutionAttackTactics Rule #8',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1009',
    name: 'ExecutionAttackTactics Rule #9',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1010',
    name: 'ExecutionAttackTactics Rule #10',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1011',
    name: 'ExecutionAttackTactics Rule #11',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1012',
    name: 'ExecutionAttackTactics Rule #12',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1013',
    name: 'ExecutionAttackTactics Rule #13',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1014',
    name: 'ExecutionAttackTactics Rule #14',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1015',
    name: 'ExecutionAttackTactics Rule #15',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1016',
    name: 'ExecutionAttackTactics Rule #16',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1017',
    name: 'ExecutionAttackTactics Rule #17',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1018',
    name: 'ExecutionAttackTactics Rule #18',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1019',
    name: 'ExecutionAttackTactics Rule #19',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1020',
    name: 'ExecutionAttackTactics Rule #20',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1021',
    name: 'ExecutionAttackTactics Rule #21',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1022',
    name: 'ExecutionAttackTactics Rule #22',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1023',
    name: 'ExecutionAttackTactics Rule #23',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1024',
    name: 'ExecutionAttackTactics Rule #24',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1025',
    name: 'ExecutionAttackTactics Rule #25',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1026',
    name: 'ExecutionAttackTactics Rule #26',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1027',
    name: 'ExecutionAttackTactics Rule #27',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1028',
    name: 'ExecutionAttackTactics Rule #28',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1029',
    name: 'ExecutionAttackTactics Rule #29',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1030',
    name: 'ExecutionAttackTactics Rule #30',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1031',
    name: 'ExecutionAttackTactics Rule #31',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1032',
    name: 'ExecutionAttackTactics Rule #32',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1033',
    name: 'ExecutionAttackTactics Rule #33',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1034',
    name: 'ExecutionAttackTactics Rule #34',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1035',
    name: 'ExecutionAttackTactics Rule #35',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1036',
    name: 'ExecutionAttackTactics Rule #36',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1037',
    name: 'ExecutionAttackTactics Rule #37',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1038',
    name: 'ExecutionAttackTactics Rule #38',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1039',
    name: 'ExecutionAttackTactics Rule #39',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1040',
    name: 'ExecutionAttackTactics Rule #40',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1041',
    name: 'ExecutionAttackTactics Rule #41',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1042',
    name: 'ExecutionAttackTactics Rule #42',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1043',
    name: 'ExecutionAttackTactics Rule #43',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1044',
    name: 'ExecutionAttackTactics Rule #44',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1045',
    name: 'ExecutionAttackTactics Rule #45',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1046',
    name: 'ExecutionAttackTactics Rule #46',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1047',
    name: 'ExecutionAttackTactics Rule #47',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1048',
    name: 'ExecutionAttackTactics Rule #48',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1049',
    name: 'ExecutionAttackTactics Rule #49',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1050',
    name: 'ExecutionAttackTactics Rule #50',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1051',
    name: 'ExecutionAttackTactics Rule #51',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1052',
    name: 'ExecutionAttackTactics Rule #52',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1053',
    name: 'ExecutionAttackTactics Rule #53',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1054',
    name: 'ExecutionAttackTactics Rule #54',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1055',
    name: 'ExecutionAttackTactics Rule #55',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1056',
    name: 'ExecutionAttackTactics Rule #56',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1057',
    name: 'ExecutionAttackTactics Rule #57',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1058',
    name: 'ExecutionAttackTactics Rule #58',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1059',
    name: 'ExecutionAttackTactics Rule #59',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1060',
    name: 'ExecutionAttackTactics Rule #60',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1061',
    name: 'ExecutionAttackTactics Rule #61',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1062',
    name: 'ExecutionAttackTactics Rule #62',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1063',
    name: 'ExecutionAttackTactics Rule #63',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1064',
    name: 'ExecutionAttackTactics Rule #64',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1065',
    name: 'ExecutionAttackTactics Rule #65',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1066',
    name: 'ExecutionAttackTactics Rule #66',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1067',
    name: 'ExecutionAttackTactics Rule #67',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1068',
    name: 'ExecutionAttackTactics Rule #68',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1069',
    name: 'ExecutionAttackTactics Rule #69',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1070',
    name: 'ExecutionAttackTactics Rule #70',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1071',
    name: 'ExecutionAttackTactics Rule #71',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1072',
    name: 'ExecutionAttackTactics Rule #72',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1073',
    name: 'ExecutionAttackTactics Rule #73',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1074',
    name: 'ExecutionAttackTactics Rule #74',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1075',
    name: 'ExecutionAttackTactics Rule #75',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1076',
    name: 'ExecutionAttackTactics Rule #76',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1077',
    name: 'ExecutionAttackTactics Rule #77',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1078',
    name: 'ExecutionAttackTactics Rule #78',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1079',
    name: 'ExecutionAttackTactics Rule #79',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1080',
    name: 'ExecutionAttackTactics Rule #80',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1081',
    name: 'ExecutionAttackTactics Rule #81',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1082',
    name: 'ExecutionAttackTactics Rule #82',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1083',
    name: 'ExecutionAttackTactics Rule #83',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1084',
    name: 'ExecutionAttackTactics Rule #84',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1085',
    name: 'ExecutionAttackTactics Rule #85',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1086',
    name: 'ExecutionAttackTactics Rule #86',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1087',
    name: 'ExecutionAttackTactics Rule #87',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1088',
    name: 'ExecutionAttackTactics Rule #88',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1089',
    name: 'ExecutionAttackTactics Rule #89',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1090',
    name: 'ExecutionAttackTactics Rule #90',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1091',
    name: 'ExecutionAttackTactics Rule #91',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1092',
    name: 'ExecutionAttackTactics Rule #92',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1093',
    name: 'ExecutionAttackTactics Rule #93',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1094',
    name: 'ExecutionAttackTactics Rule #94',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1095',
    name: 'ExecutionAttackTactics Rule #95',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1096',
    name: 'ExecutionAttackTactics Rule #96',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1097',
    name: 'ExecutionAttackTactics Rule #97',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1098',
    name: 'ExecutionAttackTactics Rule #98',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1099',
    name: 'ExecutionAttackTactics Rule #99',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1100',
    name: 'ExecutionAttackTactics Rule #100',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1101',
    name: 'ExecutionAttackTactics Rule #101',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1102',
    name: 'ExecutionAttackTactics Rule #102',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1103',
    name: 'ExecutionAttackTactics Rule #103',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1104',
    name: 'ExecutionAttackTactics Rule #104',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1105',
    name: 'ExecutionAttackTactics Rule #105',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1106',
    name: 'ExecutionAttackTactics Rule #106',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1107',
    name: 'ExecutionAttackTactics Rule #107',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1108',
    name: 'ExecutionAttackTactics Rule #108',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1109',
    name: 'ExecutionAttackTactics Rule #109',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1110',
    name: 'ExecutionAttackTactics Rule #110',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1111',
    name: 'ExecutionAttackTactics Rule #111',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1112',
    name: 'ExecutionAttackTactics Rule #112',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1113',
    name: 'ExecutionAttackTactics Rule #113',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1114',
    name: 'ExecutionAttackTactics Rule #114',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1115',
    name: 'ExecutionAttackTactics Rule #115',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1116',
    name: 'ExecutionAttackTactics Rule #116',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1117',
    name: 'ExecutionAttackTactics Rule #117',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1118',
    name: 'ExecutionAttackTactics Rule #118',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1119',
    name: 'ExecutionAttackTactics Rule #119',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1120',
    name: 'ExecutionAttackTactics Rule #120',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1121',
    name: 'ExecutionAttackTactics Rule #121',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1122',
    name: 'ExecutionAttackTactics Rule #122',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1123',
    name: 'ExecutionAttackTactics Rule #123',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1124',
    name: 'ExecutionAttackTactics Rule #124',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1125',
    name: 'ExecutionAttackTactics Rule #125',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1126',
    name: 'ExecutionAttackTactics Rule #126',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1127',
    name: 'ExecutionAttackTactics Rule #127',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1128',
    name: 'ExecutionAttackTactics Rule #128',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1129',
    name: 'ExecutionAttackTactics Rule #129',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1130',
    name: 'ExecutionAttackTactics Rule #130',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1131',
    name: 'ExecutionAttackTactics Rule #131',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1132',
    name: 'ExecutionAttackTactics Rule #132',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1133',
    name: 'ExecutionAttackTactics Rule #133',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1134',
    name: 'ExecutionAttackTactics Rule #134',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1135',
    name: 'ExecutionAttackTactics Rule #135',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1136',
    name: 'ExecutionAttackTactics Rule #136',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1137',
    name: 'ExecutionAttackTactics Rule #137',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1138',
    name: 'ExecutionAttackTactics Rule #138',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1139',
    name: 'ExecutionAttackTactics Rule #139',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1140',
    name: 'ExecutionAttackTactics Rule #140',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1141',
    name: 'ExecutionAttackTactics Rule #141',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1142',
    name: 'ExecutionAttackTactics Rule #142',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1143',
    name: 'ExecutionAttackTactics Rule #143',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1144',
    name: 'ExecutionAttackTactics Rule #144',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1145',
    name: 'ExecutionAttackTactics Rule #145',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1146',
    name: 'ExecutionAttackTactics Rule #146',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1147',
    name: 'ExecutionAttackTactics Rule #147',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1148',
    name: 'ExecutionAttackTactics Rule #148',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1149',
    name: 'ExecutionAttackTactics Rule #149',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1150',
    name: 'ExecutionAttackTactics Rule #150',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1151',
    name: 'ExecutionAttackTactics Rule #151',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1152',
    name: 'ExecutionAttackTactics Rule #152',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1153',
    name: 'ExecutionAttackTactics Rule #153',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1154',
    name: 'ExecutionAttackTactics Rule #154',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1155',
    name: 'ExecutionAttackTactics Rule #155',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1156',
    name: 'ExecutionAttackTactics Rule #156',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1157',
    name: 'ExecutionAttackTactics Rule #157',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1158',
    name: 'ExecutionAttackTactics Rule #158',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1159',
    name: 'ExecutionAttackTactics Rule #159',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1160',
    name: 'ExecutionAttackTactics Rule #160',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1161',
    name: 'ExecutionAttackTactics Rule #161',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1162',
    name: 'ExecutionAttackTactics Rule #162',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1163',
    name: 'ExecutionAttackTactics Rule #163',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1164',
    name: 'ExecutionAttackTactics Rule #164',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1165',
    name: 'ExecutionAttackTactics Rule #165',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1166',
    name: 'ExecutionAttackTactics Rule #166',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1167',
    name: 'ExecutionAttackTactics Rule #167',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1168',
    name: 'ExecutionAttackTactics Rule #168',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1169',
    name: 'ExecutionAttackTactics Rule #169',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1170',
    name: 'ExecutionAttackTactics Rule #170',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1171',
    name: 'ExecutionAttackTactics Rule #171',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1172',
    name: 'ExecutionAttackTactics Rule #172',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1173',
    name: 'ExecutionAttackTactics Rule #173',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1174',
    name: 'ExecutionAttackTactics Rule #174',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1175',
    name: 'ExecutionAttackTactics Rule #175',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1176',
    name: 'ExecutionAttackTactics Rule #176',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1177',
    name: 'ExecutionAttackTactics Rule #177',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1178',
    name: 'ExecutionAttackTactics Rule #178',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1179',
    name: 'ExecutionAttackTactics Rule #179',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1180',
    name: 'ExecutionAttackTactics Rule #180',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1181',
    name: 'ExecutionAttackTactics Rule #181',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1182',
    name: 'ExecutionAttackTactics Rule #182',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1183',
    name: 'ExecutionAttackTactics Rule #183',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1184',
    name: 'ExecutionAttackTactics Rule #184',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1185',
    name: 'ExecutionAttackTactics Rule #185',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1186',
    name: 'ExecutionAttackTactics Rule #186',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1187',
    name: 'ExecutionAttackTactics Rule #187',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1188',
    name: 'ExecutionAttackTactics Rule #188',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1189',
    name: 'ExecutionAttackTactics Rule #189',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1190',
    name: 'ExecutionAttackTactics Rule #190',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1191',
    name: 'ExecutionAttackTactics Rule #191',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1192',
    name: 'ExecutionAttackTactics Rule #192',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1193',
    name: 'ExecutionAttackTactics Rule #193',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1194',
    name: 'ExecutionAttackTactics Rule #194',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1195',
    name: 'ExecutionAttackTactics Rule #195',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1196',
    name: 'ExecutionAttackTactics Rule #196',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1197',
    name: 'ExecutionAttackTactics Rule #197',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1198',
    name: 'ExecutionAttackTactics Rule #198',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1199',
    name: 'ExecutionAttackTactics Rule #199',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1200',
    name: 'ExecutionAttackTactics Rule #200',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1201',
    name: 'ExecutionAttackTactics Rule #201',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1202',
    name: 'ExecutionAttackTactics Rule #202',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1203',
    name: 'ExecutionAttackTactics Rule #203',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1204',
    name: 'ExecutionAttackTactics Rule #204',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1205',
    name: 'ExecutionAttackTactics Rule #205',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1206',
    name: 'ExecutionAttackTactics Rule #206',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1207',
    name: 'ExecutionAttackTactics Rule #207',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1208',
    name: 'ExecutionAttackTactics Rule #208',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1209',
    name: 'ExecutionAttackTactics Rule #209',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1210',
    name: 'ExecutionAttackTactics Rule #210',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1211',
    name: 'ExecutionAttackTactics Rule #211',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1212',
    name: 'ExecutionAttackTactics Rule #212',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1213',
    name: 'ExecutionAttackTactics Rule #213',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1214',
    name: 'ExecutionAttackTactics Rule #214',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1215',
    name: 'ExecutionAttackTactics Rule #215',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1216',
    name: 'ExecutionAttackTactics Rule #216',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1217',
    name: 'ExecutionAttackTactics Rule #217',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1218',
    name: 'ExecutionAttackTactics Rule #218',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1219',
    name: 'ExecutionAttackTactics Rule #219',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1220',
    name: 'ExecutionAttackTactics Rule #220',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1221',
    name: 'ExecutionAttackTactics Rule #221',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1222',
    name: 'ExecutionAttackTactics Rule #222',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1223',
    name: 'ExecutionAttackTactics Rule #223',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1224',
    name: 'ExecutionAttackTactics Rule #224',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1225',
    name: 'ExecutionAttackTactics Rule #225',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1226',
    name: 'ExecutionAttackTactics Rule #226',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1227',
    name: 'ExecutionAttackTactics Rule #227',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1228',
    name: 'ExecutionAttackTactics Rule #228',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1229',
    name: 'ExecutionAttackTactics Rule #229',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1230',
    name: 'ExecutionAttackTactics Rule #230',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1231',
    name: 'ExecutionAttackTactics Rule #231',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1232',
    name: 'ExecutionAttackTactics Rule #232',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1233',
    name: 'ExecutionAttackTactics Rule #233',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1234',
    name: 'ExecutionAttackTactics Rule #234',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1235',
    name: 'ExecutionAttackTactics Rule #235',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1236',
    name: 'ExecutionAttackTactics Rule #236',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1237',
    name: 'ExecutionAttackTactics Rule #237',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1238',
    name: 'ExecutionAttackTactics Rule #238',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1239',
    name: 'ExecutionAttackTactics Rule #239',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1240',
    name: 'ExecutionAttackTactics Rule #240',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1241',
    name: 'ExecutionAttackTactics Rule #241',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1242',
    name: 'ExecutionAttackTactics Rule #242',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1243',
    name: 'ExecutionAttackTactics Rule #243',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1244',
    name: 'ExecutionAttackTactics Rule #244',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1245',
    name: 'ExecutionAttackTactics Rule #245',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1246',
    name: 'ExecutionAttackTactics Rule #246',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1247',
    name: 'ExecutionAttackTactics Rule #247',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1248',
    name: 'ExecutionAttackTactics Rule #248',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1249',
    name: 'ExecutionAttackTactics Rule #249',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1250',
    name: 'ExecutionAttackTactics Rule #250',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1251',
    name: 'ExecutionAttackTactics Rule #251',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1252',
    name: 'ExecutionAttackTactics Rule #252',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1253',
    name: 'ExecutionAttackTactics Rule #253',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1254',
    name: 'ExecutionAttackTactics Rule #254',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1255',
    name: 'ExecutionAttackTactics Rule #255',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1256',
    name: 'ExecutionAttackTactics Rule #256',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1257',
    name: 'ExecutionAttackTactics Rule #257',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1258',
    name: 'ExecutionAttackTactics Rule #258',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1259',
    name: 'ExecutionAttackTactics Rule #259',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1260',
    name: 'ExecutionAttackTactics Rule #260',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1261',
    name: 'ExecutionAttackTactics Rule #261',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1262',
    name: 'ExecutionAttackTactics Rule #262',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1263',
    name: 'ExecutionAttackTactics Rule #263',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1264',
    name: 'ExecutionAttackTactics Rule #264',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1265',
    name: 'ExecutionAttackTactics Rule #265',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1266',
    name: 'ExecutionAttackTactics Rule #266',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1267',
    name: 'ExecutionAttackTactics Rule #267',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1268',
    name: 'ExecutionAttackTactics Rule #268',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1269',
    name: 'ExecutionAttackTactics Rule #269',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1270',
    name: 'ExecutionAttackTactics Rule #270',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1271',
    name: 'ExecutionAttackTactics Rule #271',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1272',
    name: 'ExecutionAttackTactics Rule #272',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1273',
    name: 'ExecutionAttackTactics Rule #273',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1274',
    name: 'ExecutionAttackTactics Rule #274',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1275',
    name: 'ExecutionAttackTactics Rule #275',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1276',
    name: 'ExecutionAttackTactics Rule #276',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1277',
    name: 'ExecutionAttackTactics Rule #277',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1278',
    name: 'ExecutionAttackTactics Rule #278',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1279',
    name: 'ExecutionAttackTactics Rule #279',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1280',
    name: 'ExecutionAttackTactics Rule #280',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1281',
    name: 'ExecutionAttackTactics Rule #281',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1282',
    name: 'ExecutionAttackTactics Rule #282',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1283',
    name: 'ExecutionAttackTactics Rule #283',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1284',
    name: 'ExecutionAttackTactics Rule #284',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1285',
    name: 'ExecutionAttackTactics Rule #285',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1286',
    name: 'ExecutionAttackTactics Rule #286',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1287',
    name: 'ExecutionAttackTactics Rule #287',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1288',
    name: 'ExecutionAttackTactics Rule #288',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1289',
    name: 'ExecutionAttackTactics Rule #289',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1290',
    name: 'ExecutionAttackTactics Rule #290',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1291',
    name: 'ExecutionAttackTactics Rule #291',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1292',
    name: 'ExecutionAttackTactics Rule #292',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1293',
    name: 'ExecutionAttackTactics Rule #293',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1294',
    name: 'ExecutionAttackTactics Rule #294',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1295',
    name: 'ExecutionAttackTactics Rule #295',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1296',
    name: 'ExecutionAttackTactics Rule #296',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1297',
    name: 'ExecutionAttackTactics Rule #297',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1298',
    name: 'ExecutionAttackTactics Rule #298',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1299',
    name: 'ExecutionAttackTactics Rule #299',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1300',
    name: 'ExecutionAttackTactics Rule #300',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1301',
    name: 'ExecutionAttackTactics Rule #301',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1302',
    name: 'ExecutionAttackTactics Rule #302',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1303',
    name: 'ExecutionAttackTactics Rule #303',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1304',
    name: 'ExecutionAttackTactics Rule #304',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1305',
    name: 'ExecutionAttackTactics Rule #305',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1306',
    name: 'ExecutionAttackTactics Rule #306',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1307',
    name: 'ExecutionAttackTactics Rule #307',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1308',
    name: 'ExecutionAttackTactics Rule #308',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1309',
    name: 'ExecutionAttackTactics Rule #309',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1310',
    name: 'ExecutionAttackTactics Rule #310',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1311',
    name: 'ExecutionAttackTactics Rule #311',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1312',
    name: 'ExecutionAttackTactics Rule #312',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1313',
    name: 'ExecutionAttackTactics Rule #313',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1314',
    name: 'ExecutionAttackTactics Rule #314',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1315',
    name: 'ExecutionAttackTactics Rule #315',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1316',
    name: 'ExecutionAttackTactics Rule #316',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1317',
    name: 'ExecutionAttackTactics Rule #317',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1318',
    name: 'ExecutionAttackTactics Rule #318',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1319',
    name: 'ExecutionAttackTactics Rule #319',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1320',
    name: 'ExecutionAttackTactics Rule #320',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1321',
    name: 'ExecutionAttackTactics Rule #321',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1322',
    name: 'ExecutionAttackTactics Rule #322',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1323',
    name: 'ExecutionAttackTactics Rule #323',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1324',
    name: 'ExecutionAttackTactics Rule #324',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1325',
    name: 'ExecutionAttackTactics Rule #325',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1326',
    name: 'ExecutionAttackTactics Rule #326',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1327',
    name: 'ExecutionAttackTactics Rule #327',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1328',
    name: 'ExecutionAttackTactics Rule #328',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1329',
    name: 'ExecutionAttackTactics Rule #329',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1330',
    name: 'ExecutionAttackTactics Rule #330',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1331',
    name: 'ExecutionAttackTactics Rule #331',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1332',
    name: 'ExecutionAttackTactics Rule #332',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1333',
    name: 'ExecutionAttackTactics Rule #333',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1334',
    name: 'ExecutionAttackTactics Rule #334',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1335',
    name: 'ExecutionAttackTactics Rule #335',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1336',
    name: 'ExecutionAttackTactics Rule #336',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1337',
    name: 'ExecutionAttackTactics Rule #337',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1338',
    name: 'ExecutionAttackTactics Rule #338',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1339',
    name: 'ExecutionAttackTactics Rule #339',
    category: 'and serverless execution',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1340',
    name: 'ExecutionAttackTactics Rule #340',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1341',
    name: 'ExecutionAttackTactics Rule #341',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1342',
    name: 'ExecutionAttackTactics Rule #342',
    category: 'WMI process creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1343',
    name: 'ExecutionAttackTactics Rule #343',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1344',
    name: 'ExecutionAttackTactics Rule #344',
    category: 'PowerShell encoded scripts',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1345',
    name: 'ExecutionAttackTactics Rule #345',
    category: 'Windows Command Shell',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1346',
    name: 'ExecutionAttackTactics Rule #346',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1347',
    name: 'ExecutionAttackTactics Rule #347',
    category: 'and serverless execution',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1348',
    name: 'ExecutionAttackTactics Rule #348',
    category: 'PowerShell encoded scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1349',
    name: 'ExecutionAttackTactics Rule #349',
    category: 'Windows Command Shell',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0002-T1350',
    name: 'ExecutionAttackTactics Rule #350',
    category: 'WMI process creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0002_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0002_DATASET.slice(0, 20);
    return MITRE_TA0002_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
