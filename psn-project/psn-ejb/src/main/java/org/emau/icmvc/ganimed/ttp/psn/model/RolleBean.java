package org.emau.icmvc.ganimed.ttp.psn.model;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="rolle")
public class RolleBean implements Serializable
{
  private static final long serialVersionUID = 1L;

  private Integer intId;
  private String strRolle;
  
 
  @Id
  @Column(name="id")
  @GeneratedValue
  public Integer getId()
  {
    return this.intId;
  }
  
  public void setId (Integer int_Id)
  {
    this.intId = int_Id;
  }
  
  @Column(name="rolle")
  public String getRolle()
  {
    return this.strRolle;
  }
  
  public void setRolle(String str_Rolle)
  {
    this.strRolle = str_Rolle;
  }
} 