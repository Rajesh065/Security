/**
 * MITRE ATT&CK Enterprise Matrix: CommandAndControlTactics
 * Threat Scope: DNS tunneling, encrypted HTTPS beaconing, multi-hop proxy routing, and web protocol channels
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

export const MITRE_TA0010_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0010-T1001',
    name: 'CommandAndControlTactics Rule #1',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1002',
    name: 'CommandAndControlTactics Rule #2',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1003',
    name: 'CommandAndControlTactics Rule #3',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1004',
    name: 'CommandAndControlTactics Rule #4',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1005',
    name: 'CommandAndControlTactics Rule #5',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1006',
    name: 'CommandAndControlTactics Rule #6',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1007',
    name: 'CommandAndControlTactics Rule #7',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1008',
    name: 'CommandAndControlTactics Rule #8',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1009',
    name: 'CommandAndControlTactics Rule #9',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1010',
    name: 'CommandAndControlTactics Rule #10',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1011',
    name: 'CommandAndControlTactics Rule #11',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1012',
    name: 'CommandAndControlTactics Rule #12',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1013',
    name: 'CommandAndControlTactics Rule #13',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1014',
    name: 'CommandAndControlTactics Rule #14',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1015',
    name: 'CommandAndControlTactics Rule #15',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1016',
    name: 'CommandAndControlTactics Rule #16',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1017',
    name: 'CommandAndControlTactics Rule #17',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1018',
    name: 'CommandAndControlTactics Rule #18',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1019',
    name: 'CommandAndControlTactics Rule #19',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1020',
    name: 'CommandAndControlTactics Rule #20',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1021',
    name: 'CommandAndControlTactics Rule #21',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1022',
    name: 'CommandAndControlTactics Rule #22',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1023',
    name: 'CommandAndControlTactics Rule #23',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1024',
    name: 'CommandAndControlTactics Rule #24',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1025',
    name: 'CommandAndControlTactics Rule #25',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1026',
    name: 'CommandAndControlTactics Rule #26',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1027',
    name: 'CommandAndControlTactics Rule #27',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1028',
    name: 'CommandAndControlTactics Rule #28',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1029',
    name: 'CommandAndControlTactics Rule #29',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1030',
    name: 'CommandAndControlTactics Rule #30',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1031',
    name: 'CommandAndControlTactics Rule #31',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1032',
    name: 'CommandAndControlTactics Rule #32',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1033',
    name: 'CommandAndControlTactics Rule #33',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1034',
    name: 'CommandAndControlTactics Rule #34',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1035',
    name: 'CommandAndControlTactics Rule #35',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1036',
    name: 'CommandAndControlTactics Rule #36',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1037',
    name: 'CommandAndControlTactics Rule #37',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1038',
    name: 'CommandAndControlTactics Rule #38',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1039',
    name: 'CommandAndControlTactics Rule #39',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1040',
    name: 'CommandAndControlTactics Rule #40',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1041',
    name: 'CommandAndControlTactics Rule #41',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1042',
    name: 'CommandAndControlTactics Rule #42',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1043',
    name: 'CommandAndControlTactics Rule #43',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1044',
    name: 'CommandAndControlTactics Rule #44',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1045',
    name: 'CommandAndControlTactics Rule #45',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1046',
    name: 'CommandAndControlTactics Rule #46',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1047',
    name: 'CommandAndControlTactics Rule #47',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1048',
    name: 'CommandAndControlTactics Rule #48',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1049',
    name: 'CommandAndControlTactics Rule #49',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1050',
    name: 'CommandAndControlTactics Rule #50',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1051',
    name: 'CommandAndControlTactics Rule #51',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1052',
    name: 'CommandAndControlTactics Rule #52',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1053',
    name: 'CommandAndControlTactics Rule #53',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1054',
    name: 'CommandAndControlTactics Rule #54',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1055',
    name: 'CommandAndControlTactics Rule #55',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1056',
    name: 'CommandAndControlTactics Rule #56',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1057',
    name: 'CommandAndControlTactics Rule #57',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1058',
    name: 'CommandAndControlTactics Rule #58',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1059',
    name: 'CommandAndControlTactics Rule #59',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1060',
    name: 'CommandAndControlTactics Rule #60',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1061',
    name: 'CommandAndControlTactics Rule #61',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1062',
    name: 'CommandAndControlTactics Rule #62',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1063',
    name: 'CommandAndControlTactics Rule #63',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1064',
    name: 'CommandAndControlTactics Rule #64',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1065',
    name: 'CommandAndControlTactics Rule #65',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1066',
    name: 'CommandAndControlTactics Rule #66',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1067',
    name: 'CommandAndControlTactics Rule #67',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1068',
    name: 'CommandAndControlTactics Rule #68',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1069',
    name: 'CommandAndControlTactics Rule #69',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1070',
    name: 'CommandAndControlTactics Rule #70',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1071',
    name: 'CommandAndControlTactics Rule #71',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1072',
    name: 'CommandAndControlTactics Rule #72',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1073',
    name: 'CommandAndControlTactics Rule #73',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1074',
    name: 'CommandAndControlTactics Rule #74',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1075',
    name: 'CommandAndControlTactics Rule #75',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1076',
    name: 'CommandAndControlTactics Rule #76',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1077',
    name: 'CommandAndControlTactics Rule #77',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1078',
    name: 'CommandAndControlTactics Rule #78',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1079',
    name: 'CommandAndControlTactics Rule #79',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1080',
    name: 'CommandAndControlTactics Rule #80',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1081',
    name: 'CommandAndControlTactics Rule #81',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1082',
    name: 'CommandAndControlTactics Rule #82',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1083',
    name: 'CommandAndControlTactics Rule #83',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1084',
    name: 'CommandAndControlTactics Rule #84',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1085',
    name: 'CommandAndControlTactics Rule #85',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1086',
    name: 'CommandAndControlTactics Rule #86',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1087',
    name: 'CommandAndControlTactics Rule #87',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1088',
    name: 'CommandAndControlTactics Rule #88',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1089',
    name: 'CommandAndControlTactics Rule #89',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1090',
    name: 'CommandAndControlTactics Rule #90',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1091',
    name: 'CommandAndControlTactics Rule #91',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1092',
    name: 'CommandAndControlTactics Rule #92',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1093',
    name: 'CommandAndControlTactics Rule #93',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1094',
    name: 'CommandAndControlTactics Rule #94',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1095',
    name: 'CommandAndControlTactics Rule #95',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1096',
    name: 'CommandAndControlTactics Rule #96',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1097',
    name: 'CommandAndControlTactics Rule #97',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1098',
    name: 'CommandAndControlTactics Rule #98',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1099',
    name: 'CommandAndControlTactics Rule #99',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1100',
    name: 'CommandAndControlTactics Rule #100',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1101',
    name: 'CommandAndControlTactics Rule #101',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1102',
    name: 'CommandAndControlTactics Rule #102',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1103',
    name: 'CommandAndControlTactics Rule #103',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1104',
    name: 'CommandAndControlTactics Rule #104',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1105',
    name: 'CommandAndControlTactics Rule #105',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1106',
    name: 'CommandAndControlTactics Rule #106',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1107',
    name: 'CommandAndControlTactics Rule #107',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1108',
    name: 'CommandAndControlTactics Rule #108',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1109',
    name: 'CommandAndControlTactics Rule #109',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1110',
    name: 'CommandAndControlTactics Rule #110',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1111',
    name: 'CommandAndControlTactics Rule #111',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1112',
    name: 'CommandAndControlTactics Rule #112',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1113',
    name: 'CommandAndControlTactics Rule #113',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1114',
    name: 'CommandAndControlTactics Rule #114',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1115',
    name: 'CommandAndControlTactics Rule #115',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1116',
    name: 'CommandAndControlTactics Rule #116',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1117',
    name: 'CommandAndControlTactics Rule #117',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1118',
    name: 'CommandAndControlTactics Rule #118',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1119',
    name: 'CommandAndControlTactics Rule #119',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1120',
    name: 'CommandAndControlTactics Rule #120',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1121',
    name: 'CommandAndControlTactics Rule #121',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1122',
    name: 'CommandAndControlTactics Rule #122',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1123',
    name: 'CommandAndControlTactics Rule #123',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1124',
    name: 'CommandAndControlTactics Rule #124',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1125',
    name: 'CommandAndControlTactics Rule #125',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1126',
    name: 'CommandAndControlTactics Rule #126',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1127',
    name: 'CommandAndControlTactics Rule #127',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1128',
    name: 'CommandAndControlTactics Rule #128',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1129',
    name: 'CommandAndControlTactics Rule #129',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1130',
    name: 'CommandAndControlTactics Rule #130',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1131',
    name: 'CommandAndControlTactics Rule #131',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1132',
    name: 'CommandAndControlTactics Rule #132',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1133',
    name: 'CommandAndControlTactics Rule #133',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1134',
    name: 'CommandAndControlTactics Rule #134',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1135',
    name: 'CommandAndControlTactics Rule #135',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1136',
    name: 'CommandAndControlTactics Rule #136',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1137',
    name: 'CommandAndControlTactics Rule #137',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1138',
    name: 'CommandAndControlTactics Rule #138',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1139',
    name: 'CommandAndControlTactics Rule #139',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1140',
    name: 'CommandAndControlTactics Rule #140',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1141',
    name: 'CommandAndControlTactics Rule #141',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1142',
    name: 'CommandAndControlTactics Rule #142',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1143',
    name: 'CommandAndControlTactics Rule #143',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1144',
    name: 'CommandAndControlTactics Rule #144',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1145',
    name: 'CommandAndControlTactics Rule #145',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1146',
    name: 'CommandAndControlTactics Rule #146',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1147',
    name: 'CommandAndControlTactics Rule #147',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1148',
    name: 'CommandAndControlTactics Rule #148',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1149',
    name: 'CommandAndControlTactics Rule #149',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1150',
    name: 'CommandAndControlTactics Rule #150',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1151',
    name: 'CommandAndControlTactics Rule #151',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1152',
    name: 'CommandAndControlTactics Rule #152',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1153',
    name: 'CommandAndControlTactics Rule #153',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1154',
    name: 'CommandAndControlTactics Rule #154',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1155',
    name: 'CommandAndControlTactics Rule #155',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1156',
    name: 'CommandAndControlTactics Rule #156',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1157',
    name: 'CommandAndControlTactics Rule #157',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1158',
    name: 'CommandAndControlTactics Rule #158',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1159',
    name: 'CommandAndControlTactics Rule #159',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1160',
    name: 'CommandAndControlTactics Rule #160',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1161',
    name: 'CommandAndControlTactics Rule #161',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1162',
    name: 'CommandAndControlTactics Rule #162',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1163',
    name: 'CommandAndControlTactics Rule #163',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1164',
    name: 'CommandAndControlTactics Rule #164',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1165',
    name: 'CommandAndControlTactics Rule #165',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1166',
    name: 'CommandAndControlTactics Rule #166',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1167',
    name: 'CommandAndControlTactics Rule #167',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1168',
    name: 'CommandAndControlTactics Rule #168',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1169',
    name: 'CommandAndControlTactics Rule #169',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1170',
    name: 'CommandAndControlTactics Rule #170',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1171',
    name: 'CommandAndControlTactics Rule #171',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1172',
    name: 'CommandAndControlTactics Rule #172',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1173',
    name: 'CommandAndControlTactics Rule #173',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1174',
    name: 'CommandAndControlTactics Rule #174',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1175',
    name: 'CommandAndControlTactics Rule #175',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1176',
    name: 'CommandAndControlTactics Rule #176',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1177',
    name: 'CommandAndControlTactics Rule #177',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1178',
    name: 'CommandAndControlTactics Rule #178',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1179',
    name: 'CommandAndControlTactics Rule #179',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1180',
    name: 'CommandAndControlTactics Rule #180',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1181',
    name: 'CommandAndControlTactics Rule #181',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1182',
    name: 'CommandAndControlTactics Rule #182',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1183',
    name: 'CommandAndControlTactics Rule #183',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1184',
    name: 'CommandAndControlTactics Rule #184',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1185',
    name: 'CommandAndControlTactics Rule #185',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1186',
    name: 'CommandAndControlTactics Rule #186',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1187',
    name: 'CommandAndControlTactics Rule #187',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1188',
    name: 'CommandAndControlTactics Rule #188',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1189',
    name: 'CommandAndControlTactics Rule #189',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1190',
    name: 'CommandAndControlTactics Rule #190',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1191',
    name: 'CommandAndControlTactics Rule #191',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1192',
    name: 'CommandAndControlTactics Rule #192',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1193',
    name: 'CommandAndControlTactics Rule #193',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1194',
    name: 'CommandAndControlTactics Rule #194',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1195',
    name: 'CommandAndControlTactics Rule #195',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1196',
    name: 'CommandAndControlTactics Rule #196',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1197',
    name: 'CommandAndControlTactics Rule #197',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1198',
    name: 'CommandAndControlTactics Rule #198',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1199',
    name: 'CommandAndControlTactics Rule #199',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1200',
    name: 'CommandAndControlTactics Rule #200',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1201',
    name: 'CommandAndControlTactics Rule #201',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1202',
    name: 'CommandAndControlTactics Rule #202',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1203',
    name: 'CommandAndControlTactics Rule #203',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1204',
    name: 'CommandAndControlTactics Rule #204',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1205',
    name: 'CommandAndControlTactics Rule #205',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1206',
    name: 'CommandAndControlTactics Rule #206',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1207',
    name: 'CommandAndControlTactics Rule #207',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1208',
    name: 'CommandAndControlTactics Rule #208',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1209',
    name: 'CommandAndControlTactics Rule #209',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1210',
    name: 'CommandAndControlTactics Rule #210',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1211',
    name: 'CommandAndControlTactics Rule #211',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1212',
    name: 'CommandAndControlTactics Rule #212',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1213',
    name: 'CommandAndControlTactics Rule #213',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1214',
    name: 'CommandAndControlTactics Rule #214',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1215',
    name: 'CommandAndControlTactics Rule #215',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1216',
    name: 'CommandAndControlTactics Rule #216',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1217',
    name: 'CommandAndControlTactics Rule #217',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1218',
    name: 'CommandAndControlTactics Rule #218',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1219',
    name: 'CommandAndControlTactics Rule #219',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1220',
    name: 'CommandAndControlTactics Rule #220',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1221',
    name: 'CommandAndControlTactics Rule #221',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1222',
    name: 'CommandAndControlTactics Rule #222',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1223',
    name: 'CommandAndControlTactics Rule #223',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1224',
    name: 'CommandAndControlTactics Rule #224',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1225',
    name: 'CommandAndControlTactics Rule #225',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1226',
    name: 'CommandAndControlTactics Rule #226',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1227',
    name: 'CommandAndControlTactics Rule #227',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1228',
    name: 'CommandAndControlTactics Rule #228',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1229',
    name: 'CommandAndControlTactics Rule #229',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1230',
    name: 'CommandAndControlTactics Rule #230',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1231',
    name: 'CommandAndControlTactics Rule #231',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1232',
    name: 'CommandAndControlTactics Rule #232',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1233',
    name: 'CommandAndControlTactics Rule #233',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1234',
    name: 'CommandAndControlTactics Rule #234',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1235',
    name: 'CommandAndControlTactics Rule #235',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1236',
    name: 'CommandAndControlTactics Rule #236',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1237',
    name: 'CommandAndControlTactics Rule #237',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1238',
    name: 'CommandAndControlTactics Rule #238',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1239',
    name: 'CommandAndControlTactics Rule #239',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1240',
    name: 'CommandAndControlTactics Rule #240',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1241',
    name: 'CommandAndControlTactics Rule #241',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1242',
    name: 'CommandAndControlTactics Rule #242',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1243',
    name: 'CommandAndControlTactics Rule #243',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1244',
    name: 'CommandAndControlTactics Rule #244',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1245',
    name: 'CommandAndControlTactics Rule #245',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1246',
    name: 'CommandAndControlTactics Rule #246',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1247',
    name: 'CommandAndControlTactics Rule #247',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1248',
    name: 'CommandAndControlTactics Rule #248',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1249',
    name: 'CommandAndControlTactics Rule #249',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1250',
    name: 'CommandAndControlTactics Rule #250',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1251',
    name: 'CommandAndControlTactics Rule #251',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1252',
    name: 'CommandAndControlTactics Rule #252',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1253',
    name: 'CommandAndControlTactics Rule #253',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1254',
    name: 'CommandAndControlTactics Rule #254',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1255',
    name: 'CommandAndControlTactics Rule #255',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1256',
    name: 'CommandAndControlTactics Rule #256',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1257',
    name: 'CommandAndControlTactics Rule #257',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1258',
    name: 'CommandAndControlTactics Rule #258',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1259',
    name: 'CommandAndControlTactics Rule #259',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1260',
    name: 'CommandAndControlTactics Rule #260',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1261',
    name: 'CommandAndControlTactics Rule #261',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1262',
    name: 'CommandAndControlTactics Rule #262',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1263',
    name: 'CommandAndControlTactics Rule #263',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1264',
    name: 'CommandAndControlTactics Rule #264',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1265',
    name: 'CommandAndControlTactics Rule #265',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1266',
    name: 'CommandAndControlTactics Rule #266',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1267',
    name: 'CommandAndControlTactics Rule #267',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1268',
    name: 'CommandAndControlTactics Rule #268',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1269',
    name: 'CommandAndControlTactics Rule #269',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1270',
    name: 'CommandAndControlTactics Rule #270',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1271',
    name: 'CommandAndControlTactics Rule #271',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1272',
    name: 'CommandAndControlTactics Rule #272',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1273',
    name: 'CommandAndControlTactics Rule #273',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1274',
    name: 'CommandAndControlTactics Rule #274',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1275',
    name: 'CommandAndControlTactics Rule #275',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1276',
    name: 'CommandAndControlTactics Rule #276',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1277',
    name: 'CommandAndControlTactics Rule #277',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1278',
    name: 'CommandAndControlTactics Rule #278',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1279',
    name: 'CommandAndControlTactics Rule #279',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1280',
    name: 'CommandAndControlTactics Rule #280',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1281',
    name: 'CommandAndControlTactics Rule #281',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1282',
    name: 'CommandAndControlTactics Rule #282',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1283',
    name: 'CommandAndControlTactics Rule #283',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1284',
    name: 'CommandAndControlTactics Rule #284',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1285',
    name: 'CommandAndControlTactics Rule #285',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1286',
    name: 'CommandAndControlTactics Rule #286',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1287',
    name: 'CommandAndControlTactics Rule #287',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1288',
    name: 'CommandAndControlTactics Rule #288',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1289',
    name: 'CommandAndControlTactics Rule #289',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1290',
    name: 'CommandAndControlTactics Rule #290',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1291',
    name: 'CommandAndControlTactics Rule #291',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1292',
    name: 'CommandAndControlTactics Rule #292',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1293',
    name: 'CommandAndControlTactics Rule #293',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1294',
    name: 'CommandAndControlTactics Rule #294',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1295',
    name: 'CommandAndControlTactics Rule #295',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1296',
    name: 'CommandAndControlTactics Rule #296',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1297',
    name: 'CommandAndControlTactics Rule #297',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1298',
    name: 'CommandAndControlTactics Rule #298',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1299',
    name: 'CommandAndControlTactics Rule #299',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1300',
    name: 'CommandAndControlTactics Rule #300',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1301',
    name: 'CommandAndControlTactics Rule #301',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1302',
    name: 'CommandAndControlTactics Rule #302',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1303',
    name: 'CommandAndControlTactics Rule #303',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1304',
    name: 'CommandAndControlTactics Rule #304',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1305',
    name: 'CommandAndControlTactics Rule #305',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1306',
    name: 'CommandAndControlTactics Rule #306',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1307',
    name: 'CommandAndControlTactics Rule #307',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1308',
    name: 'CommandAndControlTactics Rule #308',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1309',
    name: 'CommandAndControlTactics Rule #309',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1310',
    name: 'CommandAndControlTactics Rule #310',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1311',
    name: 'CommandAndControlTactics Rule #311',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1312',
    name: 'CommandAndControlTactics Rule #312',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1313',
    name: 'CommandAndControlTactics Rule #313',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1314',
    name: 'CommandAndControlTactics Rule #314',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1315',
    name: 'CommandAndControlTactics Rule #315',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1316',
    name: 'CommandAndControlTactics Rule #316',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1317',
    name: 'CommandAndControlTactics Rule #317',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1318',
    name: 'CommandAndControlTactics Rule #318',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1319',
    name: 'CommandAndControlTactics Rule #319',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1320',
    name: 'CommandAndControlTactics Rule #320',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1321',
    name: 'CommandAndControlTactics Rule #321',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1322',
    name: 'CommandAndControlTactics Rule #322',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1323',
    name: 'CommandAndControlTactics Rule #323',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1324',
    name: 'CommandAndControlTactics Rule #324',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1325',
    name: 'CommandAndControlTactics Rule #325',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1326',
    name: 'CommandAndControlTactics Rule #326',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1327',
    name: 'CommandAndControlTactics Rule #327',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1328',
    name: 'CommandAndControlTactics Rule #328',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1329',
    name: 'CommandAndControlTactics Rule #329',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1330',
    name: 'CommandAndControlTactics Rule #330',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1331',
    name: 'CommandAndControlTactics Rule #331',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1332',
    name: 'CommandAndControlTactics Rule #332',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1333',
    name: 'CommandAndControlTactics Rule #333',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1334',
    name: 'CommandAndControlTactics Rule #334',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1335',
    name: 'CommandAndControlTactics Rule #335',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1336',
    name: 'CommandAndControlTactics Rule #336',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1337',
    name: 'CommandAndControlTactics Rule #337',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1338',
    name: 'CommandAndControlTactics Rule #338',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1339',
    name: 'CommandAndControlTactics Rule #339',
    category: 'and web protocol channels',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1340',
    name: 'CommandAndControlTactics Rule #340',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1341',
    name: 'CommandAndControlTactics Rule #341',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1342',
    name: 'CommandAndControlTactics Rule #342',
    category: 'multi-hop proxy routing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1343',
    name: 'CommandAndControlTactics Rule #343',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1344',
    name: 'CommandAndControlTactics Rule #344',
    category: 'DNS tunneling',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1345',
    name: 'CommandAndControlTactics Rule #345',
    category: 'encrypted HTTPS beaconing',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1346',
    name: 'CommandAndControlTactics Rule #346',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1347',
    name: 'CommandAndControlTactics Rule #347',
    category: 'and web protocol channels',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1348',
    name: 'CommandAndControlTactics Rule #348',
    category: 'DNS tunneling',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1349',
    name: 'CommandAndControlTactics Rule #349',
    category: 'encrypted HTTPS beaconing',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0010-T1350',
    name: 'CommandAndControlTactics Rule #350',
    category: 'multi-hop proxy routing',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0010_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0010_DATASET.slice(0, 20);
    return MITRE_TA0010_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
