/**
 * Copyright 2013 AppDynamics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */




package com.appdynamics.snmp.util;

import java.util.ArrayList;

public class CustomNotification
{
    protected static boolean IS_HEALTH_RULE_VIOLATION;

    protected static String APP_NAME="";
    protected static String APP_ID="";
    protected static String PVN_ALERT_TIME="";
    protected static String PRIORITY="";
    protected static String SEVERITY="";
    protected static String TAG="";
    protected static String POLICY_NAME="";
    protected static String POLICY_ID="";
    protected static String PVN_TIME_PERIOD_IN_MINUTES="";
    protected static String AFFECTED_ENTITY_TYPE="";
    protected static String AFFECTED_ENTITY_NAME="";
    protected static String AFFECTED_ENTITY_ID="";
    protected static Integer NUMBER_OF_EVALUATION_ENTITIES;
    protected static ArrayList<Evaluation_Entity> entities;

    protected static String EN_TIME="";
    protected static String EN_NAME="";
    protected static String EN_ID="";
    protected static String EN_INTERVAL_IN_MINUTES="";
    protected static Integer NUMBER_OF_EVENT_TYPES;
    protected static ArrayList<Event_Type> event_types;
    protected static Integer NUMBER_OF_EVENT_SUMMARIES;
    protected static ArrayList<Event_Summary> event_summaries;

    protected static class Evaluation_Entity
    {
        public Evaluation_Entity() {}
        public String EVALUATION_ENTITY_TYPE="";
        public String EVALUATION_ENTITY_NAME="";
        public String EVALUATION_ENTITY_ID="";
        public Integer NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY;
        public ArrayList<Triggered_Condition> triggers;
    }

    protected static class Event_Type {
        public Event_Type() {}
        public String EVENT_TYPE="";
        public Integer EVENT_TYPE_NUM;
    }

    protected static class Event_Summary {
        public Event_Summary() {}
        public String EVENT_SUMMARY_ID="";
        public String EVENT_SUMMARY_TIME="";
        public String EVENT_SUMMARY_TYPE="";
        public String EVENT_SUMMARY_SEVERITY="";
        public String EVENT_SUMMARY_STRING="";
    }

    protected static class Triggered_Condition {
        public Triggered_Condition() {};
        public String SCOPE_TYPE_x="";
        public String SCOPE_NAME_x="";
        public String SCOPE_ID_x="";
        public String CONDITION_NAME_x="";
        public String CONDITION_ID_x="";
        public String OPERATOR_x="";
        public String CONDITION_UNIT_TYPE_x="";
        public String USE_DEFAULT_BASELINE_x="";
        public String BASELINE_NAME_x="";
        public String BASELINE_ID_x="";
        public String THRESHOLD_VALUE_x="";
        public String OBSERVED_VALUE_x="";
    }

    protected static String SUMMARY_MESSAGE="";
    protected static String INCIDENT_ID="";
    protected static String DEEP_LINK_URL="";
    protected static String HR_EVENT_TYPE = "NON_POLICY_EVENT";
    protected static String IP_ADDRESSES;
    protected static String NODES="";
    protected static String TIERS="";
    protected static String BTs="";
    protected static String MACHINES="";
    protected static String TYPE="";
    protected static String SUBTYPE="";
}
