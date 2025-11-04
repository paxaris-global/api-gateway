package dto;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RealmProductRole {

    private Long id;

    private String realmName;

    private String productName;

    private String roleName;

    private List<RealmProductRoleUrl> urls;
}
