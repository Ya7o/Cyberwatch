import itertools
from cyberwatch.qualification_decision import ORIGIN_PRIORITY, QualificationDecision, precedence
from cyberwatch.qualification_policy import QualificationCandidate, choose_winner, reconcile

def _decision(item_id, field, origin, value, decision="APPLIED"):
    return QualificationDecision(item_id,"SRC",field,"Inconnu",value,value,origin,"HIGH",decision=decision)

def test_precedence_is_total_and_pairwise_stable():
    origins=list(ORIGIN_PRIORITY);assert len({precedence(origin) for origin in origins})==len(origins)
    for left,right in itertools.combinations(origins,2):
        winner=choose_winner([QualificationCandidate("I","S","Sector",left,left),QualificationCandidate("I","S","Sector",right,right)])
        assert winner.origin==(left if precedence(left)<precedence(right) else right)

def test_reconcile_rejects_lower_priority_and_explains_winner(make_item):
    item=make_item(sector="Industrie");result=reconcile([item],[_decision(item.Item_ID,"Sector","MANUAL_REFERENCE","Santé"),_decision(item.Item_ID,"Sector","SAFE_NAME_RULE","Industrie")]);by_origin={row.origin:row for row in result}
    assert item.Sector=="Santé";assert by_origin["MANUAL_REFERENCE"].decision=="APPLIED";assert by_origin["SAFE_NAME_RULE"].decision=="REJECTED_LOWER_PRIORITY";assert by_origin["SAFE_NAME_RULE"].rejected_reason=="lower_priority";assert by_origin["SAFE_NAME_RULE"].winning_origin=="MANUAL_REFERENCE";assert by_origin["SAFE_NAME_RULE"].winning_value=="Santé"

def test_reconcile_is_independent_of_candidate_order(make_item):
    for field in ("Sector","Location","Threat"):
        first=make_item();second=make_item();left=reconcile([first],[_decision(first.Item_ID,field,"ORG_SECTOR_REGISTRY","A"),_decision(first.Item_ID,field,"STRUCTURED_SOURCE","B")]);right=reconcile([second],[_decision(second.Item_ID,field,"STRUCTURED_SOURCE","B"),_decision(second.Item_ID,field,"ORG_SECTOR_REGISTRY","A")]);assert getattr(first,field)==getattr(second,field)=="B";assert [(x.origin,x.decision) for x in left]==[(x.origin,x.decision) for x in right]

def test_existing_rejection_keeps_reason_and_gets_winner(make_item):
    item=make_item();result={row.origin:row for row in reconcile([item],[_decision(item.Item_ID,"Sector","STRUCTURED_SOURCE","Santé"),_decision(item.Item_ID,"Sector","LLM_SOURCE_FALLBACK","Industrie","REJECTED_POLICY_DISABLED")])};rejected=result["LLM_SOURCE_FALLBACK"];assert rejected.rejected_reason=="policy_disabled";assert rejected.winning_origin=="STRUCTURED_SOURCE";assert rejected.winning_value=="Santé"
