package com.caas.pac;

import java.util.*;

/**
 * Represents a single policy statement.
 */
public class PolicyStatement {
    private String sid;
    private PolicyEffect effect;
    private List<PolicyAction> actions;
    private List<String> resources;
    private List<String> principals;
    private Map<String, Object> conditions;

    public PolicyStatement(String sid, PolicyEffect effect, 
                          List<PolicyAction> actions, List<String> resources) {
        this.sid = sid;
        this.effect = effect;
        this.actions = actions;
        this.resources = resources;
        this.principals = new ArrayList<>();
        this.conditions = new HashMap<>();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("Sid", sid);
        map.put("Effect", effect.getValue());
        
        List<String> actionValues = new ArrayList<>();
        for (PolicyAction action : actions) {
            actionValues.add(action.getValue());
        }
        map.put("Actions", actionValues);
        
        map.put("Resources", resources);
        
        if (!principals.isEmpty()) {
            map.put("Principals", principals);
        }
        
        if (!conditions.isEmpty()) {
            map.put("Conditions", conditions);
        }
        
        return map;
    }

    // Getters and Setters
    public String getSid() {
        return sid;
    }

    public void setSid(String sid) {
        this.sid = sid;
    }

    public PolicyEffect getEffect() {
        return effect;
    }

    public void setEffect(PolicyEffect effect) {
        this.effect = effect;
    }

    public List<PolicyAction> getActions() {
        return actions;
    }

    public void setActions(List<PolicyAction> actions) {
        this.actions = actions;
    }

    public List<String> getResources() {
        return resources;
    }

    public void setResources(List<String> resources) {
        this.resources = resources;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<String> principals) {
        this.principals = principals;
    }

    public Map<String, Object> getConditions() {
        return conditions;
    }

    public void setConditions(Map<String, Object> conditions) {
        this.conditions = conditions;
    }
}
