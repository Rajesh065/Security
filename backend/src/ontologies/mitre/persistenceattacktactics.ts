/**
 * MITRE ATT&CK Enterprise Matrix: PersistenceAttackTactics
 * Threat Scope: Registry run keys, scheduled tasks/cron jobs, account creation, and boot initialization scripts
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

export const MITRE_TA0003_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0003-T1001',
    name: 'PersistenceAttackTactics Rule #1',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1002',
    name: 'PersistenceAttackTactics Rule #2',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1003',
    name: 'PersistenceAttackTactics Rule #3',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1004',
    name: 'PersistenceAttackTactics Rule #4',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1005',
    name: 'PersistenceAttackTactics Rule #5',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1006',
    name: 'PersistenceAttackTactics Rule #6',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1007',
    name: 'PersistenceAttackTactics Rule #7',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1008',
    name: 'PersistenceAttackTactics Rule #8',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1009',
    name: 'PersistenceAttackTactics Rule #9',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1010',
    name: 'PersistenceAttackTactics Rule #10',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1011',
    name: 'PersistenceAttackTactics Rule #11',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1012',
    name: 'PersistenceAttackTactics Rule #12',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1013',
    name: 'PersistenceAttackTactics Rule #13',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1014',
    name: 'PersistenceAttackTactics Rule #14',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1015',
    name: 'PersistenceAttackTactics Rule #15',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1016',
    name: 'PersistenceAttackTactics Rule #16',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1017',
    name: 'PersistenceAttackTactics Rule #17',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1018',
    name: 'PersistenceAttackTactics Rule #18',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1019',
    name: 'PersistenceAttackTactics Rule #19',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1020',
    name: 'PersistenceAttackTactics Rule #20',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1021',
    name: 'PersistenceAttackTactics Rule #21',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1022',
    name: 'PersistenceAttackTactics Rule #22',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1023',
    name: 'PersistenceAttackTactics Rule #23',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1024',
    name: 'PersistenceAttackTactics Rule #24',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1025',
    name: 'PersistenceAttackTactics Rule #25',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1026',
    name: 'PersistenceAttackTactics Rule #26',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1027',
    name: 'PersistenceAttackTactics Rule #27',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1028',
    name: 'PersistenceAttackTactics Rule #28',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1029',
    name: 'PersistenceAttackTactics Rule #29',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1030',
    name: 'PersistenceAttackTactics Rule #30',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1031',
    name: 'PersistenceAttackTactics Rule #31',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1032',
    name: 'PersistenceAttackTactics Rule #32',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1033',
    name: 'PersistenceAttackTactics Rule #33',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1034',
    name: 'PersistenceAttackTactics Rule #34',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1035',
    name: 'PersistenceAttackTactics Rule #35',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1036',
    name: 'PersistenceAttackTactics Rule #36',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1037',
    name: 'PersistenceAttackTactics Rule #37',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1038',
    name: 'PersistenceAttackTactics Rule #38',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1039',
    name: 'PersistenceAttackTactics Rule #39',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1040',
    name: 'PersistenceAttackTactics Rule #40',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1041',
    name: 'PersistenceAttackTactics Rule #41',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1042',
    name: 'PersistenceAttackTactics Rule #42',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1043',
    name: 'PersistenceAttackTactics Rule #43',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1044',
    name: 'PersistenceAttackTactics Rule #44',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1045',
    name: 'PersistenceAttackTactics Rule #45',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1046',
    name: 'PersistenceAttackTactics Rule #46',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1047',
    name: 'PersistenceAttackTactics Rule #47',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1048',
    name: 'PersistenceAttackTactics Rule #48',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1049',
    name: 'PersistenceAttackTactics Rule #49',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1050',
    name: 'PersistenceAttackTactics Rule #50',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1051',
    name: 'PersistenceAttackTactics Rule #51',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1052',
    name: 'PersistenceAttackTactics Rule #52',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1053',
    name: 'PersistenceAttackTactics Rule #53',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1054',
    name: 'PersistenceAttackTactics Rule #54',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1055',
    name: 'PersistenceAttackTactics Rule #55',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1056',
    name: 'PersistenceAttackTactics Rule #56',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1057',
    name: 'PersistenceAttackTactics Rule #57',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1058',
    name: 'PersistenceAttackTactics Rule #58',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1059',
    name: 'PersistenceAttackTactics Rule #59',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1060',
    name: 'PersistenceAttackTactics Rule #60',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1061',
    name: 'PersistenceAttackTactics Rule #61',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1062',
    name: 'PersistenceAttackTactics Rule #62',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1063',
    name: 'PersistenceAttackTactics Rule #63',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1064',
    name: 'PersistenceAttackTactics Rule #64',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1065',
    name: 'PersistenceAttackTactics Rule #65',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1066',
    name: 'PersistenceAttackTactics Rule #66',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1067',
    name: 'PersistenceAttackTactics Rule #67',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1068',
    name: 'PersistenceAttackTactics Rule #68',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1069',
    name: 'PersistenceAttackTactics Rule #69',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1070',
    name: 'PersistenceAttackTactics Rule #70',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1071',
    name: 'PersistenceAttackTactics Rule #71',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1072',
    name: 'PersistenceAttackTactics Rule #72',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1073',
    name: 'PersistenceAttackTactics Rule #73',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1074',
    name: 'PersistenceAttackTactics Rule #74',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1075',
    name: 'PersistenceAttackTactics Rule #75',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1076',
    name: 'PersistenceAttackTactics Rule #76',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1077',
    name: 'PersistenceAttackTactics Rule #77',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1078',
    name: 'PersistenceAttackTactics Rule #78',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1079',
    name: 'PersistenceAttackTactics Rule #79',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1080',
    name: 'PersistenceAttackTactics Rule #80',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1081',
    name: 'PersistenceAttackTactics Rule #81',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1082',
    name: 'PersistenceAttackTactics Rule #82',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1083',
    name: 'PersistenceAttackTactics Rule #83',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1084',
    name: 'PersistenceAttackTactics Rule #84',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1085',
    name: 'PersistenceAttackTactics Rule #85',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1086',
    name: 'PersistenceAttackTactics Rule #86',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1087',
    name: 'PersistenceAttackTactics Rule #87',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1088',
    name: 'PersistenceAttackTactics Rule #88',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1089',
    name: 'PersistenceAttackTactics Rule #89',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1090',
    name: 'PersistenceAttackTactics Rule #90',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1091',
    name: 'PersistenceAttackTactics Rule #91',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1092',
    name: 'PersistenceAttackTactics Rule #92',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1093',
    name: 'PersistenceAttackTactics Rule #93',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1094',
    name: 'PersistenceAttackTactics Rule #94',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1095',
    name: 'PersistenceAttackTactics Rule #95',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1096',
    name: 'PersistenceAttackTactics Rule #96',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1097',
    name: 'PersistenceAttackTactics Rule #97',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1098',
    name: 'PersistenceAttackTactics Rule #98',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1099',
    name: 'PersistenceAttackTactics Rule #99',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1100',
    name: 'PersistenceAttackTactics Rule #100',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1101',
    name: 'PersistenceAttackTactics Rule #101',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1102',
    name: 'PersistenceAttackTactics Rule #102',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1103',
    name: 'PersistenceAttackTactics Rule #103',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1104',
    name: 'PersistenceAttackTactics Rule #104',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1105',
    name: 'PersistenceAttackTactics Rule #105',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1106',
    name: 'PersistenceAttackTactics Rule #106',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1107',
    name: 'PersistenceAttackTactics Rule #107',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1108',
    name: 'PersistenceAttackTactics Rule #108',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1109',
    name: 'PersistenceAttackTactics Rule #109',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1110',
    name: 'PersistenceAttackTactics Rule #110',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1111',
    name: 'PersistenceAttackTactics Rule #111',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1112',
    name: 'PersistenceAttackTactics Rule #112',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1113',
    name: 'PersistenceAttackTactics Rule #113',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1114',
    name: 'PersistenceAttackTactics Rule #114',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1115',
    name: 'PersistenceAttackTactics Rule #115',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1116',
    name: 'PersistenceAttackTactics Rule #116',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1117',
    name: 'PersistenceAttackTactics Rule #117',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1118',
    name: 'PersistenceAttackTactics Rule #118',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1119',
    name: 'PersistenceAttackTactics Rule #119',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1120',
    name: 'PersistenceAttackTactics Rule #120',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1121',
    name: 'PersistenceAttackTactics Rule #121',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1122',
    name: 'PersistenceAttackTactics Rule #122',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1123',
    name: 'PersistenceAttackTactics Rule #123',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1124',
    name: 'PersistenceAttackTactics Rule #124',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1125',
    name: 'PersistenceAttackTactics Rule #125',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1126',
    name: 'PersistenceAttackTactics Rule #126',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1127',
    name: 'PersistenceAttackTactics Rule #127',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1128',
    name: 'PersistenceAttackTactics Rule #128',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1129',
    name: 'PersistenceAttackTactics Rule #129',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1130',
    name: 'PersistenceAttackTactics Rule #130',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1131',
    name: 'PersistenceAttackTactics Rule #131',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1132',
    name: 'PersistenceAttackTactics Rule #132',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1133',
    name: 'PersistenceAttackTactics Rule #133',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1134',
    name: 'PersistenceAttackTactics Rule #134',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1135',
    name: 'PersistenceAttackTactics Rule #135',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1136',
    name: 'PersistenceAttackTactics Rule #136',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1137',
    name: 'PersistenceAttackTactics Rule #137',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1138',
    name: 'PersistenceAttackTactics Rule #138',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1139',
    name: 'PersistenceAttackTactics Rule #139',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1140',
    name: 'PersistenceAttackTactics Rule #140',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1141',
    name: 'PersistenceAttackTactics Rule #141',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1142',
    name: 'PersistenceAttackTactics Rule #142',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1143',
    name: 'PersistenceAttackTactics Rule #143',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1144',
    name: 'PersistenceAttackTactics Rule #144',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1145',
    name: 'PersistenceAttackTactics Rule #145',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1146',
    name: 'PersistenceAttackTactics Rule #146',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1147',
    name: 'PersistenceAttackTactics Rule #147',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1148',
    name: 'PersistenceAttackTactics Rule #148',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1149',
    name: 'PersistenceAttackTactics Rule #149',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1150',
    name: 'PersistenceAttackTactics Rule #150',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1151',
    name: 'PersistenceAttackTactics Rule #151',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1152',
    name: 'PersistenceAttackTactics Rule #152',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1153',
    name: 'PersistenceAttackTactics Rule #153',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1154',
    name: 'PersistenceAttackTactics Rule #154',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1155',
    name: 'PersistenceAttackTactics Rule #155',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1156',
    name: 'PersistenceAttackTactics Rule #156',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1157',
    name: 'PersistenceAttackTactics Rule #157',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1158',
    name: 'PersistenceAttackTactics Rule #158',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1159',
    name: 'PersistenceAttackTactics Rule #159',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1160',
    name: 'PersistenceAttackTactics Rule #160',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1161',
    name: 'PersistenceAttackTactics Rule #161',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1162',
    name: 'PersistenceAttackTactics Rule #162',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1163',
    name: 'PersistenceAttackTactics Rule #163',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1164',
    name: 'PersistenceAttackTactics Rule #164',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1165',
    name: 'PersistenceAttackTactics Rule #165',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1166',
    name: 'PersistenceAttackTactics Rule #166',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1167',
    name: 'PersistenceAttackTactics Rule #167',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1168',
    name: 'PersistenceAttackTactics Rule #168',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1169',
    name: 'PersistenceAttackTactics Rule #169',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1170',
    name: 'PersistenceAttackTactics Rule #170',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1171',
    name: 'PersistenceAttackTactics Rule #171',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1172',
    name: 'PersistenceAttackTactics Rule #172',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1173',
    name: 'PersistenceAttackTactics Rule #173',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1174',
    name: 'PersistenceAttackTactics Rule #174',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1175',
    name: 'PersistenceAttackTactics Rule #175',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1176',
    name: 'PersistenceAttackTactics Rule #176',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1177',
    name: 'PersistenceAttackTactics Rule #177',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1178',
    name: 'PersistenceAttackTactics Rule #178',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1179',
    name: 'PersistenceAttackTactics Rule #179',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1180',
    name: 'PersistenceAttackTactics Rule #180',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1181',
    name: 'PersistenceAttackTactics Rule #181',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1182',
    name: 'PersistenceAttackTactics Rule #182',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1183',
    name: 'PersistenceAttackTactics Rule #183',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1184',
    name: 'PersistenceAttackTactics Rule #184',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1185',
    name: 'PersistenceAttackTactics Rule #185',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1186',
    name: 'PersistenceAttackTactics Rule #186',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1187',
    name: 'PersistenceAttackTactics Rule #187',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1188',
    name: 'PersistenceAttackTactics Rule #188',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1189',
    name: 'PersistenceAttackTactics Rule #189',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1190',
    name: 'PersistenceAttackTactics Rule #190',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1191',
    name: 'PersistenceAttackTactics Rule #191',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1192',
    name: 'PersistenceAttackTactics Rule #192',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1193',
    name: 'PersistenceAttackTactics Rule #193',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1194',
    name: 'PersistenceAttackTactics Rule #194',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1195',
    name: 'PersistenceAttackTactics Rule #195',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1196',
    name: 'PersistenceAttackTactics Rule #196',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1197',
    name: 'PersistenceAttackTactics Rule #197',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1198',
    name: 'PersistenceAttackTactics Rule #198',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1199',
    name: 'PersistenceAttackTactics Rule #199',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1200',
    name: 'PersistenceAttackTactics Rule #200',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1201',
    name: 'PersistenceAttackTactics Rule #201',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1202',
    name: 'PersistenceAttackTactics Rule #202',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1203',
    name: 'PersistenceAttackTactics Rule #203',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1204',
    name: 'PersistenceAttackTactics Rule #204',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1205',
    name: 'PersistenceAttackTactics Rule #205',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1206',
    name: 'PersistenceAttackTactics Rule #206',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1207',
    name: 'PersistenceAttackTactics Rule #207',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1208',
    name: 'PersistenceAttackTactics Rule #208',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1209',
    name: 'PersistenceAttackTactics Rule #209',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1210',
    name: 'PersistenceAttackTactics Rule #210',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1211',
    name: 'PersistenceAttackTactics Rule #211',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1212',
    name: 'PersistenceAttackTactics Rule #212',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1213',
    name: 'PersistenceAttackTactics Rule #213',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1214',
    name: 'PersistenceAttackTactics Rule #214',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1215',
    name: 'PersistenceAttackTactics Rule #215',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1216',
    name: 'PersistenceAttackTactics Rule #216',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1217',
    name: 'PersistenceAttackTactics Rule #217',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1218',
    name: 'PersistenceAttackTactics Rule #218',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1219',
    name: 'PersistenceAttackTactics Rule #219',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1220',
    name: 'PersistenceAttackTactics Rule #220',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1221',
    name: 'PersistenceAttackTactics Rule #221',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1222',
    name: 'PersistenceAttackTactics Rule #222',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1223',
    name: 'PersistenceAttackTactics Rule #223',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1224',
    name: 'PersistenceAttackTactics Rule #224',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1225',
    name: 'PersistenceAttackTactics Rule #225',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1226',
    name: 'PersistenceAttackTactics Rule #226',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1227',
    name: 'PersistenceAttackTactics Rule #227',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1228',
    name: 'PersistenceAttackTactics Rule #228',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1229',
    name: 'PersistenceAttackTactics Rule #229',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1230',
    name: 'PersistenceAttackTactics Rule #230',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1231',
    name: 'PersistenceAttackTactics Rule #231',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1232',
    name: 'PersistenceAttackTactics Rule #232',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1233',
    name: 'PersistenceAttackTactics Rule #233',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1234',
    name: 'PersistenceAttackTactics Rule #234',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1235',
    name: 'PersistenceAttackTactics Rule #235',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1236',
    name: 'PersistenceAttackTactics Rule #236',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1237',
    name: 'PersistenceAttackTactics Rule #237',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1238',
    name: 'PersistenceAttackTactics Rule #238',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1239',
    name: 'PersistenceAttackTactics Rule #239',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1240',
    name: 'PersistenceAttackTactics Rule #240',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1241',
    name: 'PersistenceAttackTactics Rule #241',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1242',
    name: 'PersistenceAttackTactics Rule #242',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1243',
    name: 'PersistenceAttackTactics Rule #243',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1244',
    name: 'PersistenceAttackTactics Rule #244',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1245',
    name: 'PersistenceAttackTactics Rule #245',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1246',
    name: 'PersistenceAttackTactics Rule #246',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1247',
    name: 'PersistenceAttackTactics Rule #247',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1248',
    name: 'PersistenceAttackTactics Rule #248',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1249',
    name: 'PersistenceAttackTactics Rule #249',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1250',
    name: 'PersistenceAttackTactics Rule #250',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1251',
    name: 'PersistenceAttackTactics Rule #251',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1252',
    name: 'PersistenceAttackTactics Rule #252',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1253',
    name: 'PersistenceAttackTactics Rule #253',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1254',
    name: 'PersistenceAttackTactics Rule #254',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1255',
    name: 'PersistenceAttackTactics Rule #255',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1256',
    name: 'PersistenceAttackTactics Rule #256',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1257',
    name: 'PersistenceAttackTactics Rule #257',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1258',
    name: 'PersistenceAttackTactics Rule #258',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1259',
    name: 'PersistenceAttackTactics Rule #259',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1260',
    name: 'PersistenceAttackTactics Rule #260',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1261',
    name: 'PersistenceAttackTactics Rule #261',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1262',
    name: 'PersistenceAttackTactics Rule #262',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1263',
    name: 'PersistenceAttackTactics Rule #263',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1264',
    name: 'PersistenceAttackTactics Rule #264',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1265',
    name: 'PersistenceAttackTactics Rule #265',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1266',
    name: 'PersistenceAttackTactics Rule #266',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1267',
    name: 'PersistenceAttackTactics Rule #267',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1268',
    name: 'PersistenceAttackTactics Rule #268',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1269',
    name: 'PersistenceAttackTactics Rule #269',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1270',
    name: 'PersistenceAttackTactics Rule #270',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1271',
    name: 'PersistenceAttackTactics Rule #271',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1272',
    name: 'PersistenceAttackTactics Rule #272',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1273',
    name: 'PersistenceAttackTactics Rule #273',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1274',
    name: 'PersistenceAttackTactics Rule #274',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1275',
    name: 'PersistenceAttackTactics Rule #275',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1276',
    name: 'PersistenceAttackTactics Rule #276',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1277',
    name: 'PersistenceAttackTactics Rule #277',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1278',
    name: 'PersistenceAttackTactics Rule #278',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1279',
    name: 'PersistenceAttackTactics Rule #279',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1280',
    name: 'PersistenceAttackTactics Rule #280',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1281',
    name: 'PersistenceAttackTactics Rule #281',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1282',
    name: 'PersistenceAttackTactics Rule #282',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1283',
    name: 'PersistenceAttackTactics Rule #283',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1284',
    name: 'PersistenceAttackTactics Rule #284',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1285',
    name: 'PersistenceAttackTactics Rule #285',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1286',
    name: 'PersistenceAttackTactics Rule #286',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1287',
    name: 'PersistenceAttackTactics Rule #287',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1288',
    name: 'PersistenceAttackTactics Rule #288',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1289',
    name: 'PersistenceAttackTactics Rule #289',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1290',
    name: 'PersistenceAttackTactics Rule #290',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1291',
    name: 'PersistenceAttackTactics Rule #291',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1292',
    name: 'PersistenceAttackTactics Rule #292',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1293',
    name: 'PersistenceAttackTactics Rule #293',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1294',
    name: 'PersistenceAttackTactics Rule #294',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1295',
    name: 'PersistenceAttackTactics Rule #295',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1296',
    name: 'PersistenceAttackTactics Rule #296',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1297',
    name: 'PersistenceAttackTactics Rule #297',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1298',
    name: 'PersistenceAttackTactics Rule #298',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1299',
    name: 'PersistenceAttackTactics Rule #299',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1300',
    name: 'PersistenceAttackTactics Rule #300',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1301',
    name: 'PersistenceAttackTactics Rule #301',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1302',
    name: 'PersistenceAttackTactics Rule #302',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1303',
    name: 'PersistenceAttackTactics Rule #303',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1304',
    name: 'PersistenceAttackTactics Rule #304',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1305',
    name: 'PersistenceAttackTactics Rule #305',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1306',
    name: 'PersistenceAttackTactics Rule #306',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1307',
    name: 'PersistenceAttackTactics Rule #307',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1308',
    name: 'PersistenceAttackTactics Rule #308',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1309',
    name: 'PersistenceAttackTactics Rule #309',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1310',
    name: 'PersistenceAttackTactics Rule #310',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1311',
    name: 'PersistenceAttackTactics Rule #311',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1312',
    name: 'PersistenceAttackTactics Rule #312',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1313',
    name: 'PersistenceAttackTactics Rule #313',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1314',
    name: 'PersistenceAttackTactics Rule #314',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1315',
    name: 'PersistenceAttackTactics Rule #315',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1316',
    name: 'PersistenceAttackTactics Rule #316',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1317',
    name: 'PersistenceAttackTactics Rule #317',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1318',
    name: 'PersistenceAttackTactics Rule #318',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1319',
    name: 'PersistenceAttackTactics Rule #319',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1320',
    name: 'PersistenceAttackTactics Rule #320',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1321',
    name: 'PersistenceAttackTactics Rule #321',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1322',
    name: 'PersistenceAttackTactics Rule #322',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1323',
    name: 'PersistenceAttackTactics Rule #323',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1324',
    name: 'PersistenceAttackTactics Rule #324',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1325',
    name: 'PersistenceAttackTactics Rule #325',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1326',
    name: 'PersistenceAttackTactics Rule #326',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1327',
    name: 'PersistenceAttackTactics Rule #327',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1328',
    name: 'PersistenceAttackTactics Rule #328',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1329',
    name: 'PersistenceAttackTactics Rule #329',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1330',
    name: 'PersistenceAttackTactics Rule #330',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1331',
    name: 'PersistenceAttackTactics Rule #331',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1332',
    name: 'PersistenceAttackTactics Rule #332',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1333',
    name: 'PersistenceAttackTactics Rule #333',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1334',
    name: 'PersistenceAttackTactics Rule #334',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1335',
    name: 'PersistenceAttackTactics Rule #335',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1336',
    name: 'PersistenceAttackTactics Rule #336',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1337',
    name: 'PersistenceAttackTactics Rule #337',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1338',
    name: 'PersistenceAttackTactics Rule #338',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1339',
    name: 'PersistenceAttackTactics Rule #339',
    category: 'and boot initialization scripts',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1340',
    name: 'PersistenceAttackTactics Rule #340',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1341',
    name: 'PersistenceAttackTactics Rule #341',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1342',
    name: 'PersistenceAttackTactics Rule #342',
    category: 'account creation',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1343',
    name: 'PersistenceAttackTactics Rule #343',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1344',
    name: 'PersistenceAttackTactics Rule #344',
    category: 'Registry run keys',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1345',
    name: 'PersistenceAttackTactics Rule #345',
    category: 'scheduled tasks/cron jobs',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1346',
    name: 'PersistenceAttackTactics Rule #346',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1347',
    name: 'PersistenceAttackTactics Rule #347',
    category: 'and boot initialization scripts',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1348',
    name: 'PersistenceAttackTactics Rule #348',
    category: 'Registry run keys',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1349',
    name: 'PersistenceAttackTactics Rule #349',
    category: 'scheduled tasks/cron jobs',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0003-T1350',
    name: 'PersistenceAttackTactics Rule #350',
    category: 'account creation',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0003_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0003_DATASET.slice(0, 20);
    return MITRE_TA0003_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
