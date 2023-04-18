// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// noinspection ES6PreferShortImport

import { FunctionMap, MatchingFunction, Model, newModel, PolicyOp } from './model';
import { StringAdapter } from './persist/stringAdapter';
import { Adapter } from './persist/adapter';
import { FieldIndex } from './constants';
import { getLogger, logPrint } from './log';
import { DefaultEffector, Effect, Effector } from './effect';
import {
  arrayRemoveDuplicates,
  bracketCompatible,
  customIn,
  escapeAssertion,
  generatorRunAsync,
  generatorRunSync,
  getEvalValue,
  hasEval,
  replaceEval,
} from './util/util';

import { generateGFunction, generateSyncedGFunction } from './util/builtinOperators';
import { UpdatableAdapter } from './persist/updatableAdapter';
import { FilteredAdapter } from './persist/filteredAdapter';
import { BatchAdapter } from './persist/batchAdapter';
import { WatcherEx } from './persist/watcherEx';
import { DefaultRoleManager, MatchingFunc, RoleManager } from './rbac';
import { Watcher } from './persist/watcher';
import { addBinaryOp, compile, compileAsync } from 'expression-eval';

type Matcher = ((context: any) => Promise<any>) | ((context: any) => any);

// utils
type EnforceResult = Generator<(boolean | [boolean, string[]]) | Promise<boolean | [boolean, string[]]>>;

/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
export class Enforcer {
  protected modelPath: string;
  protected model: Model;
  protected fm: FunctionMap = FunctionMap.loadFunctionMap();
  protected eft: Effector = new DefaultEffector();
  private matcherMap: Map<string, Matcher> = new Map();

  protected adapter: UpdatableAdapter | FilteredAdapter | Adapter | BatchAdapter;
  protected watcher: Watcher | null = null;
  protected watcherEx: WatcherEx | null = null;
  protected rmMap: Map<string, RoleManager>;

  protected enabled = true;
  protected autoSave = true;
  protected autoBuildRoleLinks = true;
  protected autoNotifyWatcher = true;

  private getExpression(asyncCompile: boolean, exp: string): Matcher {
    const matcherKey = `${asyncCompile ? 'ASYNC[' : 'SYNC['}${exp}]`;

    addBinaryOp('in', 1, customIn);

    let expression = this.matcherMap.get(matcherKey);
    if (!expression) {
      exp = bracketCompatible(exp);
      expression = asyncCompile ? compileAsync(exp) : compile(exp);
      this.matcherMap.set(matcherKey, expression);
    }
    return expression;
  }

  /**
   * loadModel reloads the model from the model CONF file.
   * Because the policy is attached to a model,
   * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
   */
  public loadModel(): void {
    this.model = newModel();
    this.model.loadModel(this.modelPath);
    this.model.printModel();
  }

  /**
   * getModel gets the current model.
   *
   * @return the model of the enforcer.
   */
  public getModel(): Model {
    return this.model;
  }

  /**
   * setModel sets the current model.
   *
   * @param m the model.
   */
  public setModel(m: Model): void {
    this.model = m;
  }

  /**
   * getAdapter gets the current adapter.
   *
   * @return the adapter of the enforcer.
   */
  public getAdapter(): Adapter {
    return this.adapter;
  }

  /**
   * setAdapter sets the current adapter.
   *
   * @param adapter the adapter.
   */
  public setAdapter(adapter: Adapter): void {
    this.adapter = adapter;
  }

  /**
   * setWatcher sets the current watcher.
   *
   * @param watcher the watcher.
   */
  public setWatcher(watcher: Watcher): void {
    this.watcher = watcher;
    watcher.setUpdateCallback(async () => await this.loadPolicy());
  }

  /**
   * setWatcherEx sets the current watcherEx.
   *
   * @param watcherEx the watcherEx.
   */
  public setWatcherEx(watcherEx: WatcherEx): void {
    this.watcherEx = watcherEx;
  }

  /**
   * setRoleManager sets the current role manager.
   *
   * @param rm the role manager.
   */
  public setRoleManager(rm: RoleManager): void {
    this.rmMap.set('g', rm);
  }

  /**
   * setRoleManager sets the role manager for the named policy.
   *
   * @param ptype the named policy.
   * @param rm the role manager.
   */
  public setNamedRoleManager(ptype: string, rm: RoleManager): void {
    this.rmMap.set(ptype, rm);
  }

  /**
   * getRoleManager gets the current role manager.
   */
  public getRoleManager(): RoleManager {
    return <RoleManager>this.rmMap.get('g');
  }

  /**
   * getNamedRoleManager gets role manager by name.
   */
  public getNamedRoleManager(name: string): RoleManager | undefined {
    return this.rmMap.get(name);
  }

  /**
   * setEffector sets the current effector.
   *
   * @param eft the effector.
   */
  public setEffector(eft: Effector): void {
    this.eft = eft;
  }

  /**
   * clearPolicy clears all policy.
   */
  public clearPolicy(): void {
    this.model.clearPolicy();
  }

  public initRmMap(): void {
    this.rmMap = new Map<string, RoleManager>();
    const rm = this.model.model.get('g');
    if (rm) {
      for (const ptype of rm.keys()) {
        this.rmMap.set(ptype, new DefaultRoleManager(10));
      }
    }
  }

  public sortPolicies(): void {
    const policy = this.model.model.get('p')?.get('p')?.policy;
    const tokens = this.model.model.get('p')?.get('p')?.tokens;

    if (policy && tokens) {
      const priorityIndex = tokens.indexOf('p_priority');
      if (priorityIndex !== -1) {
        policy.sort((a, b) => {
          return parseInt(a[priorityIndex], 10) - parseInt(b[priorityIndex], 10);
        });
      }
    }
  }

  /**
   * loadPolicy reloads the policy from file/database.
   */
  public async loadPolicy(): Promise<void> {
    this.model.clearPolicy();
    await this.adapter.loadPolicy(this.model);

    this.sortPolicies();
    this.model.sortPoliciesBySubjectHierarchy();

    if (this.autoBuildRoleLinks) {
      await this.buildRoleLinksInternal();
    }
  }

  /**
   * loadFilteredPolicy reloads a filtered policy from file/database.
   *
   * @param filter the filter used to specify which type of policy should be loaded.
   */
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  public async loadFilteredPolicy(filter: any): Promise<boolean> {
    this.model.clearPolicy();

    this.sortPolicies();
    this.model.sortPoliciesBySubjectHierarchy();

    return this.loadIncrementalFilteredPolicy(filter);
  }

  /**
   * LoadIncrementalFilteredPolicy append a filtered policy from file/database.
   *
   * @param filter the filter used to specify which type of policy should be appended.
   */
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  public async loadIncrementalFilteredPolicy(filter: any): Promise<boolean> {
    if ('isFiltered' in this.adapter) {
      await this.adapter.loadFilteredPolicy(this.model, filter);
    } else {
      throw new Error('filtered policies are not supported by this adapter');
    }

    this.sortPolicies();

    if (this.autoBuildRoleLinks) {
      await this.buildRoleLinksInternal();
    }
    return true;
  }

  /**
   * isFiltered returns true if the loaded policy has been filtered.
   *
   * @return if the loaded policy has been filtered.
   */
  public isFiltered(): boolean {
    if ('isFiltered' in this.adapter) {
      return this.adapter.isFiltered();
    }
    return false;
  }

  /**
   * savePolicy saves the current policy (usually after changed with
   * Casbin API) back to file/database.
   */
  public async savePolicy(): Promise<boolean> {
    if (this.isFiltered()) {
      throw new Error('Cannot save a filtered policy');
    }
    const flag = await this.adapter.savePolicy(this.model);
    if (!flag) {
      return false;
    }
    if (this.watcherEx) {
      return await this.watcherEx.updateForSavePolicy(this.model);
    } else if (this.watcher) {
      return await this.watcher.update();
    }
    return true;
  }

  /**
   * enableEnforce changes the enforcing state of Casbin, when Casbin is
   * disabled, all access will be allowed by the enforce() function.
   *
   * @param enable whether to enable the enforcer.
   */
  public enableEnforce(enable: boolean): void {
    this.enabled = enable;
  }

  /**
   * enableLog changes whether to print Casbin log to the standard output.
   *
   * @param enable whether to enable Casbin's log.
   */
  public enableLog(enable: boolean): void {
    getLogger().enableLog(enable);
  }

  /**
   * enableAutoSave controls whether to save a policy rule automatically to
   * the adapter when it is added or removed.
   *
   * @param autoSave whether to enable the AutoSave feature.
   */
  public enableAutoSave(autoSave: boolean): void {
    this.autoSave = autoSave;
  }

  /**
   * enableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
   * @param enable whether to enable the AutoNotifyWatcher feature.
   */
  public enableAutoNotifyWatcher(enable: boolean): void {
    this.autoNotifyWatcher = enable;
  }

  /**
   * enableAutoBuildRoleLinks controls whether to save a policy rule
   * automatically to the adapter when it is added or removed.
   *
   * @param autoBuildRoleLinks whether to automatically build the role links.
   */
  public enableAutoBuildRoleLinks(autoBuildRoleLinks: boolean): void {
    this.autoBuildRoleLinks = autoBuildRoleLinks;
  }

  /**
   * add matching function to RoleManager by ptype
   * @param ptype g
   * @param fn the function will be added
   */
  public async addNamedMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void> {
    const rm = this.rmMap.get(ptype);
    if (rm) {
      return await (<DefaultRoleManager>rm).addMatchingFunc(fn);
    }

    throw Error('Target ptype not found.');
  }

  /**
   * add domain matching function to RoleManager by ptype
   * @param ptype g
   * @param fn the function will be added
   */
  public async addNamedDomainMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void> {
    const rm = this.rmMap.get(ptype);
    if (rm) {
      return await (<DefaultRoleManager>rm).addDomainMatchingFunc(fn);
    }
  }

  /**
   * buildRoleLinks manually rebuild the role inheritance relations.
   */
  public async buildRoleLinks(): Promise<void> {
    return this.buildRoleLinksInternal();
  }

  /**
   * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
   * @param op policy operation
   * @param ptype g
   * @param rules policies
   */
  public async buildIncrementalRoleLinks(op: PolicyOp, ptype: string, rules: string[][]): Promise<void> {
    let rm = this.rmMap.get(ptype);
    if (!rm) {
      rm = new DefaultRoleManager(10);
      this.rmMap.set(ptype, rm);
    }
    await this.model.buildIncrementalRoleLinks(rm, op, 'g', ptype, rules);
  }

  protected async buildRoleLinksInternal(): Promise<void> {
    for (const rm of this.rmMap.values()) {
      await rm.clear();
      await this.model.buildRoleLinks(this.rmMap);
    }
  }

  private *privateEnforce(asyncCompile = true, explain = false, ...rvals: any[]): EnforceResult {
    if (!this.enabled) {
      return true;
    }

    let explainIndex = -1;

    const functions: { [key: string]: any } = {};
    this.fm.getFunctions().forEach((value: any, key: string) => {
      functions[key] = value;
    });

    const astMap = this.model.model.get('g');

    astMap?.forEach((value, key) => {
      const rm = value.rm;
      functions[key] = asyncCompile ? generateGFunction(rm) : generateSyncedGFunction(rm);
    });

    const expString = this.model.model.get('m')?.get('m')?.value;
    if (!expString) {
      throw new Error('Unable to find matchers in model');
    }

    const effectExpr = this.model.model.get('e')?.get('e')?.value;
    if (!effectExpr) {
      throw new Error('Unable to find policy_effect in model');
    }

    const HasEval: boolean = hasEval(expString);
    let expression: Matcher | undefined = undefined;

    const p = this.model.model.get('p')?.get('p');
    const policyLen = p?.policy?.length;

    const rTokens = this.model.model.get('r')?.get('r')?.tokens;
    const rTokensLen = rTokens?.length;

    const effectStream = this.eft.newStream(effectExpr);

    if (policyLen && policyLen !== 0) {
      for (let i = 0; i < policyLen; i++) {
        const parameters: { [key: string]: any } = {};

        if (rTokens?.length !== rvals.length) {
          throw new Error(`invalid request size: expected ${rTokensLen}, got ${rvals.length}, rvals: ${rvals}"`);
        }

        rTokens.forEach((token, j) => {
          parameters[token] = rvals[j];
        });

        p?.tokens.forEach((token, j) => {
          parameters[token] = p?.policy[i][j];
        });

        if (HasEval) {
          const ruleNames: string[] = getEvalValue(expString);
          let expWithRule = expString;
          for (const ruleName of ruleNames) {
            if (ruleName in parameters) {
              const rule = escapeAssertion(parameters[ruleName]);
              expWithRule = replaceEval(expWithRule, ruleName, rule);
            } else {
              throw new Error(`${ruleName} not in ${parameters}`);
            }
          }
          expression = this.getExpression(asyncCompile, expWithRule);
        } else {
          if (expression === undefined) {
            expression = this.getExpression(asyncCompile, expString);
          }
        }

        const context = { ...parameters, ...functions };
        const result = asyncCompile ? yield expression(context) : expression(context);

        let eftRes: Effect;
        switch (typeof result) {
          case 'boolean':
            eftRes = result ? Effect.Allow : Effect.Indeterminate;
            break;
          case 'number':
            if (result === 0) {
              eftRes = Effect.Indeterminate;
            } else {
              eftRes = result;
            }
            break;
          case 'string':
            if (result === '') {
              eftRes = Effect.Indeterminate;
            } else {
              eftRes = Effect.Allow;
            }
            break;
          default:
            throw new Error('matcher result should only be of type boolean, number, or string');
        }

        const eft = parameters['p_eft'];
        if (eft && eftRes === Effect.Allow) {
          if (eft === 'allow') {
            eftRes = Effect.Allow;
          } else if (eft === 'deny') {
            eftRes = Effect.Deny;
          } else {
            eftRes = Effect.Indeterminate;
          }
        }

        const [res, rec, done] = effectStream.pushEffect(eftRes);

        if (rec) {
          explainIndex = i;
        }

        if (done) {
          break;
        }
      }
    } else {
      explainIndex = 0;

      const parameters: { [key: string]: any } = {};

      rTokens?.forEach((token, j): void => {
        parameters[token] = rvals[j];
      });

      p?.tokens?.forEach((token) => {
        parameters[token] = '';
      });

      expression = this.getExpression(asyncCompile, expString);
      const context = { ...parameters, ...functions };
      const result = asyncCompile ? yield expression(context) : expression(context);

      if (result) {
        effectStream.pushEffect(Effect.Allow);
      } else {
        effectStream.pushEffect(Effect.Indeterminate);
      }
    }

    const res = effectStream.current();

    // only generate the request --> result string if the message
    // is going to be logged.
    if (getLogger().isEnable()) {
      let reqStr = 'Request: ';
      for (let i = 0; i < rvals.length; i++) {
        if (i !== rvals.length - 1) {
          reqStr += `${rvals[i]}, `;
        } else {
          reqStr += rvals[i];
        }
      }
      reqStr += ` ---> ${res}`;
      logPrint(reqStr);
    }

    if (explain) {
      if (explainIndex === -1) {
        return [res, []];
      }
      return [res, p?.policy[explainIndex]];
    }

    return res;
  }

  /**
   * If the matchers does not contain an asynchronous method, call it faster.
   *
   * enforceSync decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request.
   */
  public enforceSync(...rvals: any[]): boolean {
    return generatorRunSync(this.privateEnforce(false, false, ...rvals));
  }

  /**
   * If the matchers does not contain an asynchronous method, call it faster.
   *
   * enforceSync decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request and the reason rule.
   */
  public enforceExSync(...rvals: any[]): [boolean, string[]] {
    return generatorRunSync(this.privateEnforce(false, true, ...rvals));
  }

  /**
   * Same as enforceSync. To be removed.
   */
  public enforceWithSyncCompile(...rvals: any[]): boolean {
    return this.enforceSync(...rvals);
  }

  /**
   * enforce decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request.
   */
  public async enforce(...rvals: any[]): Promise<boolean> {
    return generatorRunAsync(this.privateEnforce(true, false, ...rvals));
  }

  /**
   * enforce decides whether a "subject" can access a "object" with
   * the operation "action", input parameters are usually: (sub, obj, act).
   *
   * @param rvals the request needs to be mediated, usually an array
   *              of strings, can be class instances if ABAC is used.
   * @return whether to allow the request and the reason rule.
   */
  public async enforceEx(...rvals: any[]): Promise<[boolean, string[]]> {
    return generatorRunAsync(this.privateEnforce(true, true, ...rvals));
  }

  /**
   * batchEnforce enforces each request and returns result in a bool array.
   * @param rvals the request need to be mediated, usually an array
   *              of array of strings, can be class instances if ABAC is used.
   * @returns whether to allow the requests.
   */
  public async batchEnforce(rvals: any[]): Promise<boolean[]> {
    return await Promise.all(rvals.map((rval) => this.enforce(...rval)));
  }
  /**
   * addPolicyInternal adds a rule to the current policy.
   */
  protected async addPolicyInternal(sec: string, ptype: string, rule: string[], useWatcher: boolean): Promise<boolean> {
    if (this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.addPolicy(sec, ptype, rule);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForAddPolicy(sec, ptype, ...rule);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const ok = this.model.addPolicy(sec, ptype, rule);

    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [rule]);
    }
    return ok;
  }

  // addPolicies adds rules to the current policy.
  // removePolicies removes rules from the current policy.
  protected async addPoliciesInternal(sec: string, ptype: string, rules: string[][], useWatcher: boolean): Promise<boolean> {
    for (const rule of rules) {
      if (this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    if (this.autoSave) {
      if ('addPolicies' in this.adapter) {
        try {
          await this.adapter.addPolicies(sec, ptype, rules);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to save policy, the adapter does not implement the BatchAdapter');
      }
    }

    if (useWatcher) {
      if (this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForAddPolicies(sec, ptype, ...rules);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = await this.model.addPolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, effects);
    }
    return ok;
  }

  /**
   * updatePolicyInternal updates a rule from the current policy.
   */
  protected async updatePolicyInternal(
    sec: string,
    ptype: string,
    oldRule: string[],
    newRule: string[],
    useWatcher: boolean
  ): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, oldRule)) {
      return false;
    }

    if (this.autoSave) {
      if ('updatePolicy' in this.adapter) {
        try {
          await this.adapter.updatePolicy(sec, ptype, oldRule, newRule);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to update policy, the adapter does not implement the UpdatableAdapter');
      }
    }

    if (useWatcher) {
      if (this.watcher && this.autoNotifyWatcher) {
        // In fact I think it should wait for the respond, but they implement add_policy() like this
        // error intentionally ignored
        this.watcher.update();
      }
    }

    const ok = this.model.updatePolicy(sec, ptype, oldRule, newRule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [oldRule]);
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyAdd, ptype, [newRule]);
    }

    return ok;
  }

  /**
   * removePolicyInternal removes a rule from the current policy.
   */
  protected async removePolicyInternal(sec: string, ptype: string, rule: string[], useWatcher: boolean): Promise<boolean> {
    if (!this.model.hasPolicy(sec, ptype, rule)) {
      return false;
    }

    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.removePolicy(sec, ptype, rule);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.watcher && this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemovePolicy(sec, ptype, ...rule);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const ok = await this.model.removePolicy(sec, ptype, rule);
    if (sec === 'g' && ok) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, [rule]);
    }
    return ok;
  }

  // removePolicies removes rules from the current policy.
  protected async removePoliciesInternal(sec: string, ptype: string, rules: string[][], useWatcher: boolean): Promise<boolean> {
    for (const rule of rules) {
      if (!this.model.hasPolicy(sec, ptype, rule)) {
        return false;
      }
    }

    if (this.autoSave) {
      if ('removePolicies' in this.adapter) {
        try {
          await this.adapter.removePolicies(sec, ptype, rules);
        } catch (e) {
          if (e instanceof Error && e.message !== 'not implemented') {
            throw e;
          }
        }
      } else {
        throw new Error('cannot to save policy, the adapter does not implement the BatchAdapter');
      }
    }

    if (useWatcher) {
      if (this.watcher && this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemovePolicies(sec, ptype, ...rules);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = this.model.removePolicies(sec, ptype, rules);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  /**
   * removeFilteredPolicyInternal removes rules based on field filters from the current policy.
   */
  protected async removeFilteredPolicyInternal(
    sec: string,
    ptype: string,
    fieldIndex: number,
    fieldValues: string[],
    useWatcher: boolean
  ): Promise<boolean> {
    if (this.adapter && this.autoSave) {
      try {
        await this.adapter.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
      } catch (e) {
        if (e instanceof Error && e.message !== 'not implemented') {
          throw e;
        }
      }
    }

    if (useWatcher) {
      if (this.watcher && this.autoNotifyWatcher) {
        // error intentionally ignored
        if (this.watcherEx) {
          this.watcherEx.updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
        } else if (this.watcher) {
          this.watcher.update();
        }
      }
    }

    const [ok, effects] = this.model.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
    if (sec === 'g' && ok && effects?.length) {
      await this.buildIncrementalRoleLinks(PolicyOp.PolicyRemove, ptype, effects);
    }
    return ok;
  }

  /**
   * get field index in model.fieldMap.
   */
  public getFieldIndex(ptype: string, field: string): number {
    return this.model.getFieldIndex(ptype, field);
  }

  /**
   *  set index of field
   */
  public setFieldIndex(ptype: string, field: string, index: number): void {
    const assertion = this.model.model.get('p')?.get(ptype);
    assertion?.fieldIndexMap.set(field, index);
  }
  /**
   * getAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the subjects in policy rules of the ptype type. It actually
   *         collects the 0-index elements of the policy rules. So make sure
   *         your subject is the 0-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedSubjects(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 0);
  }

  /**
   * getAllObjects gets the list of objects that show up in the current policy.
   *
   * @return all the objects in "p" policy rules. It actually collects the
   *         1-index elements of "p" policy rules. So make sure your object
   *         is the 1-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllObjects(): Promise<string[]> {
    return this.getAllNamedObjects('p');
  }

  /**
   * getAllNamedObjects gets the list of objects that show up in the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the objects in policy rules of the ptype type. It actually
   *         collects the 1-index elements of the policy rules. So make sure
   *         your object is the 1-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedObjects(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 1);
  }

  /**
   * getAllActions gets the list of actions that show up in the current policy.
   *
   * @return all the actions in "p" policy rules. It actually collects
   *         the 2-index elements of "p" policy rules. So make sure your action
   *         is the 2-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllActions(): Promise<string[]> {
    return this.getAllNamedActions('p');
  }

  /**
   * GetAllNamedActions gets the list of actions that show up in the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return all the actions in policy rules of the ptype type. It actually
   *         collects the 2-index elements of the policy rules. So make sure
   *         your action is the 2-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedActions(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('p', ptype, 2);
  }

  /**
   * getAllRoles gets the list of roles that show up in the current policy.
   *
   * @return all the roles in "g" policy rules. It actually collects
   *         the 1-index elements of "g" policy rules. So make sure your
   *         role is the 1-index element, like (sub, role).
   *         Duplicates are removed.
   */
  public async getAllRoles(): Promise<string[]> {
    return this.getAllNamedRoles('g');
  }

  /**
   * getAllNamedRoles gets the list of roles that show up in the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @return all the subjects in policy rules of the ptype type. It actually
   *         collects the 0-index elements of the policy rules. So make
   *         sure your subject is the 0-index element, like (sub, obj, act).
   *         Duplicates are removed.
   */
  public async getAllNamedRoles(ptype: string): Promise<string[]> {
    return this.model.getValuesForFieldInPolicy('g', ptype, 1);
  }

  /**
   * getPolicy gets all the authorization rules in the policy.
   *
   * @return all the "p" policy rules.
   */
  public async getPolicy(): Promise<string[][]> {
    return this.getNamedPolicy('p');
  }

  /**
   * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "p" policy rules.
   */
  public async getFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.getFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
  }

  /**
   * getNamedPolicy gets all the authorization rules in the named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @return the "p" policy rules of the specified ptype.
   */
  public async getNamedPolicy(ptype: string): Promise<string[][]> {
    return this.model.getPolicy('p', ptype);
  }

  /**
   * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "p" policy rules of the specified ptype.
   */
  public async getFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.model.getFilteredPolicy('p', ptype, fieldIndex, ...fieldValues);
  }

  /**
   * getGroupingPolicy gets all the role inheritance rules in the policy.
   *
   * @return all the "g" policy rules.
   */
  public async getGroupingPolicy(): Promise<string[][]> {
    return this.getNamedGroupingPolicy('g');
  }

  /**
   * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value "" means not to match this field.
   * @return the filtered "g" policy rules.
   */
  public async getFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.getFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
  }

  /**
   * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @return the "g" policy rules of the specified ptype.
   */
  public async getNamedGroupingPolicy(ptype: string): Promise<string[][]> {
    return this.model.getPolicy('g', ptype);
  }

  /**
   * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return the filtered "g" policy rules of the specified ptype.
   */
  public async getFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]> {
    return this.model.getFilteredPolicy('g', ptype, fieldIndex, ...fieldValues);
  }

  /**
   * hasPolicy determines whether an authorization rule exists.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return whether the rule exists.
   */
  public async hasPolicy(...params: string[]): Promise<boolean> {
    return this.hasNamedPolicy('p', ...params);
  }

  /**
   * hasNamedPolicy determines whether a named authorization rule exists.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return whether the rule exists.
   */
  public async hasNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.model.hasPolicy('p', ptype, params);
  }

  /**
   * addPolicy adds an authorization rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async addPolicy(...params: string[]): Promise<boolean> {
    return this.addNamedPolicy('p', ...params);
  }

  /**
   * addPolicies adds authorization rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param rules the "p" policy rules, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async addPolicies(rules: string[][]): Promise<boolean> {
    return this.addNamedPolicies('p', rules);
  }

  /**
   * addNamedPolicy adds an authorization rule to the current named policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return succeeds or not.
   */
  public async addNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.addPolicyInternal('p', ptype, params, true);
  }

  /**
   * addNamedPolicies adds authorization rules to the current named policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param rules the "p" policy rules.
   * @return succeeds or not.
   */
  public async addNamedPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternal('p', ptype, rules, true);
  }

  /**
   * updatePolicy updates an authorization rule from the current policy.
   * If the rule not exists, the function returns false.
   * Otherwise the function returns true by changing it to the new rule.
   *
   * @return succeeds or not.
   * @param oldRule the policy will be remove
   * @param newRule the policy will be added
   */
  public async updatePolicy(oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updateNamedPolicy('p', oldRule, newRule);
  }

  /**
   * updateNamedPolicy updates an authorization rule from the current named policy.
   * If the rule not exists, the function returns false.
   * Otherwise the function returns true by changing it to the new rule.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param oldRule the policy rule will be remove
   * @param newRule the policy rule will be added
   * @return succeeds or not.
   */
  public async updateNamedPolicy(ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyInternal('p', ptype, oldRule, newRule, true);
  }

  /**
   * removePolicy removes an authorization rule from the current policy.
   *
   * @param params the "p" policy rule, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async removePolicy(...params: string[]): Promise<boolean> {
    return this.removeNamedPolicy('p', ...params);
  }

  /**
   * removePolicies removes an authorization rules from the current policy.
   *
   * @param rules the "p" policy rules, ptype "p" is implicitly used.
   * @return succeeds or not.
   */
  public async removePolicies(rules: string[][]): Promise<boolean> {
    return this.removeNamedPolicies('p', rules);
  }

  /**
   * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
  }

  /**
   * removeNamedPolicy removes an authorization rule from the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param params the "p" policy rule.
   * @return succeeds or not.
   */
  public async removeNamedPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.removePolicyInternal('p', ptype, params, true);
  }

  /**
   * removeNamedPolicies removes authorization rules from the current named policy.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param rules the "p" policy rules.
   * @return succeeds or not.
   */
  public async removeNamedPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.removePoliciesInternal('p', ptype, rules, true);
  }

  /**
   * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "p", "p2", "p3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyInternal('p', ptype, fieldIndex, fieldValues, true);
  }

  /**
   * hasGroupingPolicy determines whether a role inheritance rule exists.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return whether the rule exists.
   */
  public async hasGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.hasNamedGroupingPolicy('g', ...params);
  }

  /**
   * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return whether the rule exists.
   */
  public async hasNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.model.hasPolicy('g', ptype, params);
  }

  /**
   * addGroupingPolicy adds a role inheritance rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async addGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.addNamedGroupingPolicy('g', ...params);
  }

  /**
   * addGroupingPolicies adds a role inheritance rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param rules the "g" policy rules, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async addGroupingPolicies(rules: string[][]): Promise<boolean> {
    return this.addNamedGroupingPolicies('g', rules);
  }

  /**
   * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
   * If the rule already exists, the function returns false and the rule will not be added.
   * Otherwise the function returns true by adding the new rule.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return succeeds or not.
   */
  public async addNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.addPolicyInternal('g', ptype, params, true);
  }

  /**
   * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
   * If the rule already exists, the function returns false and the rules will not be added.
   * Otherwise the function returns true by adding the new rules.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param rules the "g" policy rule.
   * @return succeeds or not.
   */
  public async addNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.addPoliciesInternal('g', ptype, rules, true);
  }

  /**
   * removeGroupingPolicy removes a role inheritance rule from the current policy.
   *
   * @param params the "g" policy rule, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async removeGroupingPolicy(...params: string[]): Promise<boolean> {
    return this.removeNamedGroupingPolicy('g', ...params);
  }

  /**
   * removeGroupingPolicies removes role inheritance rules from the current policy.
   *
   * @param rules the "g" policy rules, ptype "g" is implicitly used.
   * @return succeeds or not.
   */
  public async removeGroupingPolicies(rules: string[][]): Promise<boolean> {
    return this.removeNamedGroupingPolicies('g', rules);
  }

  /**
   * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
   *
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
  }

  /**
   * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param params the "g" policy rule.
   * @return succeeds or not.
   */
  public async removeNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean> {
    return this.removePolicyInternal('g', ptype, params, true);
  }

  /**
   * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param rules the "g" policy rules.
   * @return succeeds or not.
   */
  public async removeNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean> {
    return this.removePoliciesInternal('g', ptype, rules, true);
  }

  /**
   * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param fieldIndex the policy rule's start index to be matched.
   * @param fieldValues the field values to be matched, value ""
   *                    means not to match this field.
   * @return succeeds or not.
   */
  public async removeFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyInternal('g', ptype, fieldIndex, fieldValues, true);
  }

  /**
   * UpdateGroupingPolicy updates an rule to the current named policy.
   *
   * @param oldRule the old rule.
   * @param newRule the new rule.
   * @return succeeds or not.
   */
  public async updateGroupingPolicy(oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updateNamedGroupingPolicy('g', oldRule, newRule);
  }

  /**
   * updateNamedGroupingPolicy updates an rule to the current named policy.
   *
   * @param ptype the policy type, can be "g", "g2", "g3", ..
   * @param oldRule the old rule.
   * @param newRule the new rule.
   * @return succeeds or not.
   */
  public async updateNamedGroupingPolicy(ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyInternal('g', ptype, oldRule, newRule, true);
  }

  /**
   * addFunction adds a customized function.
   * @param name custom function name
   * @param func function
   */
  public async addFunction(name: string, func: MatchingFunction): Promise<void> {
    this.fm.addFunction(name, func);
  }

  public async selfAddPolicy(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    return this.addPolicyInternal(sec, ptype, rule, false);
  }

  public async selfRemovePolicy(sec: string, ptype: string, rule: string[]): Promise<boolean> {
    return this.removePolicyInternal(sec, ptype, rule, false);
  }

  public async selfRemoveFilteredPolicy(sec: string, ptype: string, fieldIndex: number, fieldValues: string[]): Promise<boolean> {
    return this.removeFilteredPolicyInternal(sec, ptype, fieldIndex, fieldValues, false);
  }

  public async selfUpdatePolicy(sec: string, ptype: string, oldRule: string[], newRule: string[]): Promise<boolean> {
    return this.updatePolicyInternal(sec, ptype, oldRule, newRule, false);
  }

  public async selfAddPolicies(sec: string, ptype: string, rule: string[][]): Promise<boolean> {
    return this.addPoliciesInternal(sec, ptype, rule, false);
  }

  public async selfRemovePolicies(sec: string, ptype: string, rule: string[][]): Promise<boolean> {
    return this.removePoliciesInternal(sec, ptype, rule, false);
  }
  /**
   * getAllSubjects gets the list of subjects that show up in the current policy.
   *
   * @return all the subjects in "p" policy rules. It actually collects the
   *         0-index elements of "p" policy rules. So make sure your subject
   *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
   */
  public async getAllSubjects(): Promise<string[]> {
    return this.getAllNamedSubjects('p');
  }
  /**
   * initWithFile initializes an enforcer with a model file and a policy file.
   * @param modelPath model file path
   * @param policyString policy CSV string
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithString(modelPath: string, policyString: string, lazyLoad = false): Promise<void> {
    const a = new StringAdapter(policyString);
    await this.initWithAdapter(modelPath, a, lazyLoad);
  }

  /**
   * initWithAdapter initializes an enforcer with a database adapter.
   * @param modelPath model file path
   * @param adapter current adapter instance
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithAdapter(modelPath: string, adapter: Adapter, lazyLoad = false): Promise<void> {
    const m = newModel(modelPath, '');
    await this.initWithModelAndAdapter(m, adapter, lazyLoad);

    this.modelPath = modelPath;
  }

  /**
   * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
   * @param m model instance
   * @param adapter current adapter instance
   * @param lazyLoad whether to load policy at initial time
   */
  public async initWithModelAndAdapter(m: Model, adapter?: Adapter, lazyLoad = false): Promise<void> {
    if (adapter) {
      this.adapter = adapter;
    }

    this.model = m;
    this.model.printModel();

    this.initRmMap();

    if (!lazyLoad && this.adapter) {
      await this.loadPolicy();
    }
  }

  /**
   * getRolesForUser gets the roles that a user has.
   *
   * @param name the user.
   * @param domain the domain.
   * @return the roles that the user has.
   */
  public async getRolesForUser(name: string, domain?: string): Promise<string[]> {
    const rm = this.rmMap.get('g');
    if (rm) {
      if (domain === undefined) {
        return rm.getRoles(name);
      } else {
        return rm.getRoles(name, domain);
      }
    }
    throw new Error("RoleManager didn't exist.");
  }

  /**
   * getUsersForRole gets the users that has a role.
   *
   * @param name the role.
   * @param domain the domain.
   * @return the users that has the role.
   */
  public async getUsersForRole(name: string, domain?: string): Promise<string[]> {
    const rm = this.rmMap.get('g');
    if (rm) {
      if (domain === undefined) {
        return rm.getUsers(name);
      } else {
        return rm.getUsers(name, domain);
      }
    }
    throw new Error("RoleManager didn't exist.");
  }

  /**
   * hasRoleForUser determines whether a user has a role.
   *
   * @param name the user.
   * @param role the role.
   * @param domain the domain.
   * @return whether the user has the role.
   */
  public async hasRoleForUser(name: string, role: string, domain?: string): Promise<boolean> {
    const roles = await this.getRolesForUser(name, domain);
    let hasRole = false;
    for (const r of roles) {
      if (r === role) {
        hasRole = true;
        break;
      }
    }

    return hasRole;
  }

  /**
   * addRoleForUser adds a role for a user.
   * Returns false if the user already has the role (aka not affected).
   *
   * @param user the user.
   * @param role the role.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async addRoleForUser(user: string, role: string, domain?: string): Promise<boolean> {
    if (domain === undefined) {
      return this.addGroupingPolicy(user, role);
    } else {
      return this.addGroupingPolicy(user, role, domain);
    }
  }

  /**
   * deleteRoleForUser deletes a role for a user.
   * Returns false if the user does not have the role (aka not affected).
   *
   * @param user the user.
   * @param role the role.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async deleteRoleForUser(user: string, role: string, domain?: string): Promise<boolean> {
    if (domain === undefined) {
      return this.removeGroupingPolicy(user, role);
    } else {
      return this.removeGroupingPolicy(user, role, domain);
    }
  }

  /**
   * deleteRolesForUser deletes all roles for a user.
   * Returns false if the user does not have any roles (aka not affected).
   *
   * @param user the user.
   * @param domain the domain.
   * @return succeeds or not.
   */
  public async deleteRolesForUser(user: string, domain?: string): Promise<boolean> {
    if (domain === undefined) {
      const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
      return this.removeFilteredGroupingPolicy(subIndex, user);
    } else {
      return this.removeFilteredGroupingPolicy(0, user, '', domain);
    }
  }

  /**
   * deleteUser deletes a user.
   * Returns false if the user does not exist (aka not affected).
   *
   * @param user the user.
   * @return succeeds or not.
   */
  public async deleteUser(user: string): Promise<boolean> {
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    const res1 = await this.removeFilteredGroupingPolicy(subIndex, user);
    const res2 = await this.removeFilteredPolicy(subIndex, user);
    return res1 || res2;
  }

  /**
   * deleteRole deletes a role.
   * Returns false if the role does not exist (aka not affected).
   *
   * @param role the role.
   * @return succeeds or not.
   */
  public async deleteRole(role: string): Promise<boolean> {
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    const res1 = await this.removeFilteredGroupingPolicy(subIndex, role);
    const res2 = await this.removeFilteredPolicy(subIndex, role);
    return res1 || res2;
  }

  /**
   * deletePermission deletes a permission.
   * Returns false if the permission does not exist (aka not affected).
   *
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async deletePermission(...permission: string[]): Promise<boolean> {
    return this.removeFilteredPolicy(1, ...permission);
  }

  /**
   * addPermissionForUser adds a permission for a user or role.
   * Returns false if the user or role already has the permission (aka not affected).
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async addPermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    permission.unshift(user);
    return this.addPolicy(...permission);
  }

  /**
   * deletePermissionForUser deletes a permission for a user or role.
   * Returns false if the user or role does not have the permission (aka not affected).
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return succeeds or not.
   */
  public async deletePermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    permission.unshift(user);
    return this.removePolicy(...permission);
  }

  /**
   * deletePermissionsForUser deletes permissions for a user or role.
   * Returns false if the user or role does not have any permissions (aka not affected).
   *
   * @param user the user.
   * @return succeeds or not.
   */
  public async deletePermissionsForUser(user: string): Promise<boolean> {
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    return this.removeFilteredPolicy(subIndex, user);
  }

  /**
   * getPermissionsForUser gets permissions for a user or role.
   *
   * @param user the user.
   * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
   */
  public async getPermissionsForUser(user: string): Promise<string[][]> {
    const subIndex = this.getFieldIndex('p', FieldIndex.Subject);
    return this.getFilteredPolicy(subIndex, user);
  }

  /**
   * hasPermissionForUser determines whether a user has a permission.
   *
   * @param user the user.
   * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
   * @return whether the user has the permission.
   */
  public async hasPermissionForUser(user: string, ...permission: string[]): Promise<boolean> {
    permission.unshift(user);
    return this.hasPolicy(...permission);
  }

  /**
   * getImplicitRolesForUser gets implicit roles that a user has.
   * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
   * For example:
   * g, alice, role:admin
   * g, role:admin, role:user
   *
   * getRolesForUser("alice") can only get: ["role:admin"].
   * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
   */
  public async getImplicitRolesForUser(name: string, ...domain: string[]): Promise<string[]> {
    const res = new Set<string>();
    const q = [name];
    let n: string | undefined;
    while ((n = q.shift()) !== undefined) {
      for (const rm of this.rmMap.values()) {
        const role = await rm.getRoles(n, ...domain);
        role.forEach((r) => {
          if (!res.has(r)) {
            res.add(r);
            q.push(r);
          }
        });
      }
    }

    return Array.from(res);
  }

  /**
   * getImplicitPermissionsForUser gets implicit permissions for a user or role.
   * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
   * For example:
   * p, admin, data1, read
   * p, alice, data2, read
   * g, alice, admin
   *
   * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
   * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
   */
  public async getImplicitPermissionsForUser(user: string, ...domain: string[]): Promise<string[][]> {
    const roles = await this.getImplicitRolesForUser(user, ...domain);
    roles.unshift(user);
    const res: string[][] = [];
    const withDomain = domain && domain.length !== 0;

    for (const n of roles) {
      if (withDomain) {
        const p = await this.getFilteredPolicy(0, n, ...domain);
        res.push(...p);
      } else {
        const p = await this.getPermissionsForUser(n);
        res.push(...p);
      }
    }

    return res;
  }

  /**
   * getImplicitResourcesForUser returns all policies that user obtaining in domain.
   */
  public async getImplicitResourcesForUser(user: string, ...domain: string[]): Promise<string[][]> {
    const permissions = await this.getImplicitPermissionsForUser(user, ...domain);
    const res: string[][] = [];
    for (const permission of permissions) {
      if (permission[0] === user) {
        res.push(permission);
        continue;
      }
      let resLocal: string[][] = [[user]];
      const tokensLength: number = permission.length;
      const t: string[][] = [];
      for (const token of permission) {
        if (token === permission[0]) {
          continue;
        }
        const tokens: string[] = await this.getImplicitUsersForRole(token, ...domain);
        tokens.push(token);
        t.push(tokens);
      }
      for (let i = 0; i < tokensLength - 1; i++) {
        const n: string[][] = [];
        for (const tokens of t[i]) {
          for (const policy of resLocal) {
            const t: string[] = [...policy];
            t.push(tokens);
            n.push(t);
          }
        }
        resLocal = n;
      }
      res.push(...resLocal);
    }
    return res;
  }

  /**
   * getImplicitUsersForRole gets implicit users that a role has.
   * Compared to getUsersForRole(), this function retrieves indirect users besides direct users.
   * For example:
   * g, alice, role:admin
   * g, role:admin, role:user
   *
   * getUsersForRole("user") can only get: ["role:admin"].
   * But getImplicitUsersForRole("user") will get: ["role:admin", "alice"].
   */
  public async getImplicitUsersForRole(role: string, ...domain: string[]): Promise<string[]> {
    const res = new Set<string>();
    const q = [role];
    let n: string | undefined;
    while ((n = q.shift()) !== undefined) {
      for (const rm of this.rmMap.values()) {
        const user = await rm.getUsers(n, ...domain);
        user.forEach((u) => {
          if (!res.has(u)) {
            res.add(u);
            q.push(u);
          }
        });
      }
    }

    return Array.from(res);
  }

  /**
   * getRolesForUserInDomain gets the roles that a user has inside a domain
   * An alias for getRolesForUser with the domain params.
   *
   * @param name the user.
   * @param domain the domain.
   * @return the roles that the user has.
   */
  public async getRolesForUserInDomain(name: string, domain: string): Promise<string[]> {
    return this.getRolesForUser(name, domain);
  }

  /**
   * getUsersForRoleInFomain gets the users that has a role inside a domain
   * An alias for getUsesForRole with the domain params.
   *
   * @param name the role.
   * @param domain the domain.
   * @return the users that has the role.
   */
  public async getUsersForRoleInDomain(name: string, domain: string): Promise<string[]> {
    return this.getUsersForRole(name, domain);
  }

  /**
   * getImplicitUsersForPermission gets implicit users for a permission.
   * For example:
   * p, admin, data1, read
   * p, bob, data1, read
   * g, alice, admin
   *
   * getImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
   * Note: only users will be returned, roles (2nd arg in "g") will be excluded.
   */
  public async getImplicitUsersForPermission(...permission: string[]): Promise<string[]> {
    const res: string[] = [];
    const policySubjects = await this.getAllSubjects();
    const subjects = arrayRemoveDuplicates([...policySubjects, ...this.model.getValuesForFieldInPolicyAllTypes('g', 0)]);
    const inherits = this.model.getValuesForFieldInPolicyAllTypes('g', 1);

    for (const user of subjects) {
      const allowed = await this.enforce(user, ...permission);
      if (allowed) {
        res.push(user);
      }
    }

    return res.filter((n) => !inherits.some((m) => n === m));
  }
}
