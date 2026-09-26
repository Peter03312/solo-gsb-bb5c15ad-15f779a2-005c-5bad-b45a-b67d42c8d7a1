import type { RuleInput } from './audit/types'

/** 首启动演示规则集：覆盖可达、部分遮蔽、完全遮蔽、共同覆盖、非法等情形 */
export function createDemoRules(): RuleInput[] {
  let n = 0
  const r = (partial: Partial<RuleInput>): RuleInput => ({
    id: `demo-${n++}`,
    name: partial.name ?? '',
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  })
  return [
    r({ name: '拦截 SSH 管理段', cidr: '192.168.1.0/24', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
    r({ name: '放行内部办公网', cidr: '10.0.0.0/8', portStart: '1024', portEnd: '65535', protocol: 'TCP', action: 'allow' }),
    r({ name: '放行内部 UDP 语音', cidr: '10.0.0.0/8', portStart: '5060', portEnd: '5061', protocol: 'UDP', action: 'allow' }),
    r({ name: '冗余：重复的 SSH 拦截（完全遮蔽）', cidr: '192.168.1.0/24', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
    r({ name: '半遮蔽：Web 端口段（80-443 被上方办公网规则夺走）', cidr: '10.0.0.0/8', portStart: '80', portEnd: '8080', protocol: 'TCP', action: 'allow' }),
    r({ name: '分段一', cidr: '172.16.0.0/25', portStart: '0', portEnd: '1024', protocol: 'UDP', action: 'deny' }),
    r({ name: '分段二', cidr: '172.16.0.128/25', portStart: '0', portEnd: '1024', protocol: 'UDP', action: 'deny' }),
    r({ name: '被共同覆盖：整个 /24 低端口 UDP', cidr: '172.16.0.0/24', portStart: '0', portEnd: '1024', protocol: 'UDP', action: 'allow' }),
    r({ name: '兜底全放行', cidr: '0.0.0.0/0', action: 'allow' }),
    r({ name: '已停用：临时下线的旧规则（不参与分析）', cidr: '203.0.113.0/24', portStart: '3306', portEnd: '3306', protocol: 'TCP', action: 'deny', enabled: false }),
    r({ name: '非法 CIDR（不参与分析）', cidr: '10.0.0.5/24', action: 'allow' }),
    r({ name: '非法端口（不参与分析）', cidr: '10.1.0.0/16', portStart: '99999', portEnd: '5', protocol: 'TCP', action: 'allow' }),
  ]
}
